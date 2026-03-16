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
#define MAX_CLIENTS 64

#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  // 24 bytes
#define TAG_SIZE   crypto_aead_xchacha20poly1305_ietf_ABYTES     // 16 bytes

static void remove_client(struct pollfd *fds, size_t *nfds, size_t i)
{
    close(fds[i].fd);

    if (i != *nfds - 1) {
        fds[i] = fds[*nfds - 1];
    }

    (*nfds)--;

    if (i < *nfds) {
        fds[i].revents = 0;
    }
}

unsigned long long encrypt_message(
    const unsigned char *plaintext, size_t pt_len,
    const unsigned char *key,
    unsigned char *nonce,
    unsigned char *ciphertext)
{
    randombytes_buf(nonce, NONCE_SIZE);  // generate random 192-bit nonce

    unsigned long long ct_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ct_len,
            plaintext, pt_len,
            NULL, 0,    // no additional data
            NULL,       // nsec not used
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
            NULL,       // nsec not used
            ciphertext, ct_len,
            NULL, 0,    // no additional data
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
                         const unsigned char *key)
{
    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[pkt_len + TAG_SIZE];

    // Encrypt the MQTT payload
    unsigned long long ct_len = encrypt_message(mqtt_packet, pkt_len, key, nonce, ciphertext);

    // Send total length first (network byte order)
    uint32_t net_len = htonl(ct_len);
    send__all(sock, (unsigned char*)&net_len, sizeof(net_len));

    // Send nonce
    send__all(sock, nonce, NONCE_SIZE);

    // Send ciphertext
    send__all(sock, ciphertext, ct_len);

    print_hex("Nonce", nonce, NONCE_SIZE);
    print_hex("Ciphertext", ciphertext, ct_len);
}

unsigned char* recv_mqtt_encrypted(int sock, const unsigned char *key, size_t *out_len)
{
    uint32_t net_len;
    recv__all(sock, (unsigned char*)&net_len, sizeof(net_len));
    uint32_t ct_len = ntohl(net_len);

    unsigned char nonce[NONCE_SIZE];
    recv__all(sock, nonce, NONCE_SIZE);

    unsigned char ciphertext[ct_len];
    recv__all(sock, ciphertext, ct_len);

    print_hex("Received Nonce", nonce, NONCE_SIZE);
    print_hex("Received Ciphertext", ciphertext, ct_len);

    unsigned char *plaintext = malloc(ct_len); // max possible size
    unsigned long long pt_len = decrypt_message(ciphertext, ct_len, nonce, key, plaintext);

    if(pt_len == 0) {
        free(plaintext);
        *out_len = 0;
        return NULL;
    }

    *out_len = pt_len;
    return plaintext;
}

void handle_mqtt_packet(unsigned char *packet, size_t pkt_len) {
    if (pkt_len < 2) return;

    unsigned char packet_type = packet[0] >> 4;

    unsigned char *payload = packet + 2;

    if (packet_type == 8) { // SUBSCRIBE
        size_t topic_len = (payload[0] << 8) | payload[1];
        char topic[topic_len + 1];
        memcpy(topic, payload + 2, topic_len);
        topic[topic_len] = '\0';
        printf("SUBSCRIBE topic: %s\n", topic);
    }
    else if (packet_type == 10) { // UNSUBSCRIBE
        size_t topic_len = (payload[0] << 8) | payload[1];
        char topic[topic_len + 1];
        memcpy(topic, payload + 2, topic_len);
        topic[topic_len] = '\0';
        printf("UNSUBSCRIBE topic: %s\n", topic);
    }
    else {
        printf("Other MQTT packet type: %d\n", packet_type);
    }
}

int main() {
    if (sodium_init() != 0) {
        printf("libsodium init failed\n");
        return -1;
    }

    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(server_pk, server_sk);

    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, server_pk, crypto_kx_PUBLICKEYBYTES);

    printf("Server PK SHA256: ");
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++)
        printf("%02x", hash[i]);
    printf("\n");

    int ret;
    int listen_fd = smqtt_socket();
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    ret = smqtt_bind(listen_fd, PORT, NULL);
    ret = smqtt_listen(listen_fd, MAX_CLIENTS);
    printf("Listening on port %d\n", PORT);

    struct pollfd fds[MAX_CLIENTS+1];
    memset(fds,0,sizeof(fds));

    fds[0].fd = listen_fd;
    fds[0].events = POLLIN;
    size_t nfds = 1;

    int loop_counter = 0;

    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    while (1) {
        if (loop_counter > 3) break;
        ret = poll(fds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            printf("poll error %d\n", ret);
            break;
        }

        if (fds[0].revents & POLLIN) {
            int new_conn_fd = smqtt_accept(listen_fd, NULL, NULL);
            printf("New client %d\n", new_conn_fd);
            if(nfds < MAX_CLIENTS) {
                ret = smqtt_broker_handshake(new_conn_fd, rx, tx, server_pk, server_sk);
                printf("Handshake returned %d\n", ret);
                if (ret != 0) {
                    printf("Handshake failed\n");
                    close(new_conn_fd);
                    continue;
                }
                print_hex("Server RX key", rx, crypto_kx_SESSIONKEYBYTES);
                print_hex("Server TX key", tx, crypto_kx_SESSIONKEYBYTES);
                fds[nfds].fd = new_conn_fd;
                fds[nfds].events = POLLIN;
                nfds++;
            } else {
                printf("Max clients reached\n");
                close(new_conn_fd);
            }

            continue;
        }

        for (size_t i = nfds-1; i > 0; i--) {
            /* disconnect / error */
            if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                printf("Client %d disconnected\n", fds[i].fd);
                remove_client(fds, &nfds, i);
            } else if (fds[i].revents & POLLIN) {
                unsigned char *plaintext;
                size_t pt_len;

                // decrypt using RX session key from handshake
                plaintext = recv_mqtt_encrypted(fds[i].fd, rx, &pt_len);

                if (plaintext && pt_len > 0) {
                    handle_mqtt_packet(plaintext, pt_len);
                    free(plaintext);
                } else {
                    printf("Failed to decrypt packet from client %d\n", fds[i].fd);
                }
            }
        }

        loop_counter++;
    }

    /* cleanup */
    for (size_t i = 0; i < nfds; i++)
        close(fds[i].fd);

    close(listen_fd);

    return 0;
}
