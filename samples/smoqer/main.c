#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "smqtt/broker.h"
#include "smqtt/common.h"

#define PORT 8900
#define MAX_CLIENTS 1024

#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES // 24 bytes
#define TAG_SIZE crypto_aead_xchacha20poly1305_ietf_ABYTES      // 16 bytes

typedef struct
{
    int uuid;
    int active;
    int fd;
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    uint32_t to_client_seq_num;
    uint32_t from_client_seq_num;
} smqtt_client_t;

smqtt_client_t *client_map[MAX_CLIENTS];
int next_client_id;

void generate_nonce(const unsigned char *key, uint32_t seq_num, unsigned char *nonce)
{
    unsigned char input[crypto_kx_SESSIONKEYBYTES + sizeof(uint32_t)];

    memcpy(input, key, crypto_kx_SESSIONKEYBYTES);

    uint32_t seq_be = htonl(seq_num);
    memcpy(input + crypto_kx_SESSIONKEYBYTES, &seq_be, sizeof(uint32_t));

    crypto_generichash(nonce, NONCE_SIZE,
                       input, sizeof(input),
                       NULL, 0);

    print_hex("Nonce: ", nonce, sizeof(nonce));
}

unsigned long long encrypt_message(
    const unsigned char *plaintext, size_t pt_len,
    const unsigned char *key,
    unsigned char *nonce,
    unsigned char *ciphertext)
{
    randombytes_buf(nonce, NONCE_SIZE); // generate random 192-bit nonce

    unsigned long long ct_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ct_len,
            plaintext, pt_len,
            NULL, 0, // no additional data
            NULL,    // nsec not used
            nonce,
            key) != 0)
    {
        fprintf(stderr, "Encryption failed!\n");
        exit(1);
    }
    return ct_len;
}

unsigned long long decrypt_message(
    const unsigned char *ciphertext, size_t ct_len,
    const unsigned char *nonce,
    const unsigned char *key,
    unsigned char *plaintext)
{
    unsigned long long pt_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL, // nsec not used
            ciphertext, ct_len,
            NULL, 0, // no additional data
            nonce,
            key) != 0)
    {
        fprintf(stderr, "Decryption failed!\n");
        return 0;
    }
    return pt_len;
}

void send_mqtt_encrypted(int sock,
                         const unsigned char *mqtt_packet, size_t pkt_len,
                         const unsigned char *key, uint32_t to_client_seq_num)
{
    printf("Sending out packet %d to client", to_client_seq_num);
    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[pkt_len + TAG_SIZE];

    // Encrypt the MQTT payload
    unsigned long long ct_len = encrypt_message(mqtt_packet, pkt_len, key, nonce, ciphertext);

    // Send total length first (network byte order)
    uint32_t net_len = htonl(ct_len);
    send__all(sock, (unsigned char *)&net_len, sizeof(net_len));

    // Send nonce
    send__all(sock, nonce, NONCE_SIZE);

    // Send ciphertext
    send__all(sock, ciphertext, ct_len);

    print_hex("Nonce", nonce, NONCE_SIZE);
    print_hex("Ciphertext", ciphertext, ct_len);
}

unsigned char *recv_mqtt_encrypted(int sock, const unsigned char *key, size_t *out_len, uint32_t from_client_seq_num)
{
    printf("Receiving packet %d from client\n", from_client_seq_num);

    uint32_t net_len;
    recv__all(sock, (unsigned char *)&net_len, sizeof(net_len));
    uint32_t ct_len = ntohl(net_len);

    unsigned char nonce[NONCE_SIZE];
    generate_nonce(key, from_client_seq_num, nonce);
    // recv__all(sock, nonce, NONCE_SIZE);

    unsigned char ciphertext[ct_len];
    recv__all(sock, ciphertext, ct_len);
    print_hex("Received Ciphertext", ciphertext, ct_len);

    unsigned char *plaintext = malloc(ct_len); // max possible size
    unsigned long long pt_len = decrypt_message(ciphertext, ct_len, nonce, key, plaintext);

    if (pt_len == 0)
    {
        free(plaintext);
        *out_len = 0;
        return NULL;
    }

    *out_len = pt_len;
    return plaintext;
}

void handle_mqtt_packet(unsigned char *packet, size_t pkt_len)
{
    if (pkt_len < 2)
        return;

    unsigned char packet_type = packet[0] >> 4;

    unsigned char *payload = packet + 2;

    if (packet_type == 8)
    { // SUBSCRIBE
        size_t topic_len = (payload[0] << 8) | payload[1];
        char topic[topic_len + 1];
        memcpy(topic, payload + 2, topic_len);
        topic[topic_len] = '\0';
        printf("SUBSCRIBE topic: %s\n", topic);
    }
    else if (packet_type == 10)
    { // UNSUBSCRIBE
        size_t topic_len = (payload[0] << 8) | payload[1];
        char topic[topic_len + 1];
        memcpy(topic, payload + 2, topic_len);
        topic[topic_len] = '\0';
        printf("UNSUBSCRIBE topic: %s\n", topic);
    }
    else
    {
        printf("Other MQTT packet type: %d\n", packet_type);
    }
}

static int add_client(int fd, unsigned char *rx_key, unsigned char *tx_key)
{
    client_map[fd] = calloc(1, sizeof(smqtt_client_t));
    smqtt_client_t *new_client = client_map[fd];
    if (new_client == NULL)
    {
        printf("Error allocating new client\n");
        return -1;
    }

    new_client->active = 1;
    new_client->fd = fd;
    new_client->uuid = next_client_id++;
    memcpy(new_client->rx_key, rx_key, crypto_kx_SESSIONKEYBYTES);
    memcpy(new_client->tx_key, tx_key, crypto_kx_SESSIONKEYBYTES);
    new_client->to_client_seq_num = 0;
    new_client->from_client_seq_num = 0;

    return 0;
}

static int remove_client(int fd)
{
    smqtt_client_t *out_client = client_map[fd];
    sodium_memzero(out_client->rx_key, crypto_kx_SESSIONKEYBYTES);
    sodium_memzero(out_client->tx_key, crypto_kx_SESSIONKEYBYTES);

    free(out_client);

    return 0;
}

static void print_all_clients()
{
    int curr_clients = 0;
    for (size_t i = 0; i < MAX_CLIENTS; i++)
    {
        if (client_map[i] != NULL && client_map[i]->active)
        {
            curr_clients++;
            printf("Active Client %ld\n", i);
            printf("uuid: %d\n", client_map[i]->uuid);
            printf("fd: %d\n\n", client_map[i]->fd);
        }
    }
    printf("Current Clients: %d\n\n", curr_clients);
}

smqtt_client_t *get_client(int fd)
{
    for (size_t i = 0; i < MAX_CLIENTS; i++)
    {
        if (client_map[i] != NULL && client_map[i]->fd == fd)
        {
            return client_map[i];
        }
    }

    printf("fd not found in map\n");
    return NULL;
}

int main()
{
    if (sodium_init() != 0)
        return -1;

    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);

    // "public certificate" to deliver smoqer's public key
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, server_pk, crypto_kx_PUBLICKEYBYTES);
    printf("Server PK SHA256: ");
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");

    next_client_id = 1;

    int listen_fd = smqtt_socket();
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (smqtt_bind(listen_fd, PORT, NULL) < 0)
    {
        perror("Bind failed");
        return -1;
    }
    smqtt_listen(listen_fd, MAX_CLIENTS);
    printf("Listening on port %d\n", PORT);

    struct pollfd fds[MAX_CLIENTS + 1];
    memset(fds, 0, sizeof(fds));
    memset(client_map, 0, sizeof(client_map));

    fds[0].fd = listen_fd;
    fds[0].events = POLLIN;
    size_t nfds = 1;

    while (1)
    {
        print_all_clients();

        int ret = poll(fds, nfds, -1);
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        // New Client Logic
        if (fds[0].revents & POLLIN)
        {
            int new_fd = smqtt_accept(listen_fd, NULL, NULL);
            if (new_fd >= 0)
            {
                if (nfds < MAX_CLIENTS)
                {
                    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
                    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

                    if (smqtt_broker_handshake(new_fd, rx, tx, server_pk, server_sk) == 0)
                    {
                        add_client(new_fd, rx, tx);
                        fds[nfds].fd = new_fd;
                        fds[nfds].events = POLLIN;
                        fds[nfds].revents = 0;
                        nfds++;
                        printf("Client %d connected (Total: %zu)\n", new_fd, nfds - 1);
                    }
                    else
                    {
                        printf("Handshake error\n");
                        close(new_fd);
                    }
                }
                else
                {
                    printf("Rejected: Too many clients or high FD\n");
                    close(new_fd);
                }
            }
            else
            {
                printf("Accept error\n");
                close(new_fd);
            }
        }

        for (size_t i = nfds - 1; i > 0; i--)
        {
            if (fds[i].revents & POLLIN)
            {
                size_t pt_len = 0;
                smqtt_client_t *curr_client = get_client(fds[i].fd);
                unsigned char *plaintext = recv_mqtt_encrypted(curr_client->fd, curr_client->rx_key, &pt_len, curr_client->from_client_seq_num);
                curr_client->from_client_seq_num++;
                if (plaintext)
                {
                    handle_mqtt_packet(plaintext, pt_len);
                    free(plaintext);
                }
            }

            if (fds[i].revents & POLLHUP)
            {
                // client disconnected
                printf("Removing Client uuid: %d\n", client_map[fds[i].fd]->uuid);
                remove_client(fds[i].fd);
                nfds--;
            }
        }
    }

    return 0;
}