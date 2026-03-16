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

#include "smqtt/client.h"
#include "smqtt/common.h"

#define PORT 8900

#define STDIN_BUF_SIZE 256
#define MAX_MENU 3
#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  // 24 bytes
#define TAG_SIZE   crypto_aead_xchacha20poly1305_ietf_ABYTES     // 16 bytes

enum menu {
    DISC = 0,
    SUB,
    UNSUB,
    PUB,
};

int print_menu(void){
    printf("-----------Choose Item-----------\n");
    printf("1. Subscribe\n");
    printf("2. Unsubscribe\n");
    printf("3. Publish\n");
    printf("0. Disconnect\n");

    return 0;
}

int prompt_input(char *input_buf) {
    if (fgets(input_buf, STDIN_BUF_SIZE, stdin) != NULL) {
        input_buf[strcspn(input_buf, "\n")] = '\0';
        return 0;
    }
    return -1;
}

long get_choice(char *choice){
    char *end;
    long ret = strtol(choice, &end, 10);
    if (*end != '\0'){
        fprintf(stderr, "choice must be a number\n");
        return -1;
    }
    if (ret < 0 || ret > MAX_MENU) {
        fprintf(stderr, "choice cannot exceed possible choices\n");
        return -1;
    }

    return ret;
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

#define MQTT_PKT_SUB 0x82  // SUBSCRIBE packet type + flags
#define MQTT_PKT_UNSUB 0xA2 // UNSUBSCRIBE packet type + flags

unsigned char* build_mqtt_sub_packet(const char *topic, size_t *out_len)
{
    size_t topic_len = strlen(topic);
    size_t pkt_len = 2 + topic_len + 1; // Topic length (2 bytes) + topic + QoS (1 byte)
    unsigned char *payload = malloc(pkt_len);
    payload[0] = (topic_len >> 8) & 0xFF;
    payload[1] = topic_len & 0xFF;
    memcpy(payload+2, topic, topic_len);
    payload[2 + topic_len] = 0x00; // QoS 0

    // fixed header + remaining length
    *out_len = 1 + 1 + pkt_len; // type byte + remaining length + payload
    unsigned char *packet = malloc(*out_len);
    packet[0] = MQTT_PKT_SUB;
    packet[1] = pkt_len;       // assume < 127 bytes for simplicity
    memcpy(packet+2, payload, pkt_len);
    free(payload);
    return packet;
}

unsigned char* build_mqtt_unsub_packet(const char *topic, size_t *out_len)
{
    size_t topic_len = strlen(topic);
    size_t pkt_len = 2 + topic_len; // Topic length (2 bytes) + topic
    unsigned char *payload = malloc(pkt_len);
    payload[0] = (topic_len >> 8) & 0xFF;
    payload[1] = topic_len & 0xFF;
    memcpy(payload+2, topic, topic_len);

    // fixed header + remaining length
    *out_len = 1 + 1 + pkt_len;
    unsigned char *packet = malloc(*out_len);
    packet[0] = MQTT_PKT_UNSUB;
    packet[1] = pkt_len;       // assume < 127 bytes
    memcpy(packet+2, payload, pkt_len);
    free(payload);
    return packet;
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }

    if (argc < 3) {
        printf("Usage: %s <server_ip> <server_public_key_hash_hex>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    const char *hash_hex = argv[2];

    unsigned char pinned_hash[crypto_hash_sha256_BYTES];
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
        sscanf(hash_hex + 2*i, "%2hhx", &pinned_hash[i]);
    }

    int sock_fd;
    int ret;
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];

    sock_fd = smqtt_socket();
    ret = smqtt_connect(sock_fd, server_ip, PORT);
    printf("Connected to %s:%d\n", server_ip, PORT);

    ret = smqtt_client_handshake(sock_fd, rx, tx, pinned_hash);
    printf("Handshake returned %d\n", ret);
    if (ret != 0) {
        return -1;
    }
    print_hex("Client RX key", rx, crypto_kx_SESSIONKEYBYTES);
    print_hex("Client TX key", tx, crypto_kx_SESSIONKEYBYTES);

    long choice;
    int run = 1;

    while (run) {
        print_menu();
        char stdin_buffer[STDIN_BUF_SIZE];
        if (fgets(stdin_buffer, sizeof(stdin_buffer), stdin) == NULL) {
            fprintf(stderr, "Input error.\n");
            break;
        }

        stdin_buffer[strcspn(stdin_buffer, "\n")] = '\0';
        choice = get_choice(stdin_buffer);
        if (choice == -1)
        {
            fprintf(stderr, "Choice error. Try Again.\n");
            continue;
        }

        switch (choice) {
            case SUB:
                printf("Enter topic:");
                prompt_input(stdin_buffer);
                printf("Topic: %s\n", stdin_buffer);

                size_t pkt_len;
                unsigned char *sub_pkt = build_mqtt_sub_packet(stdin_buffer, &pkt_len);
                send_mqtt_encrypted(sock_fd, sub_pkt, pkt_len, tx);
                free(sub_pkt);
                break;

            case UNSUB:
                printf("Enter topic:");
                prompt_input(stdin_buffer);
                printf("Topic: %s\n", stdin_buffer);

                unsigned char *unsub_pkt = build_mqtt_unsub_packet(stdin_buffer, &pkt_len);
                send_mqtt_encrypted(sock_fd, unsub_pkt, pkt_len, tx);
                free(unsub_pkt);
                break;
            case PUB:
                // prompt topic_str, prompt data, send publish
                printf("Enter topic:");
                prompt_input(stdin_buffer);
                printf("Topic: %s\n", stdin_buffer);
                printf("Enter data:");
                prompt_input(stdin_buffer);
                printf("Data: %s\n", stdin_buffer);
                break;
            case DISC:
                run = 0;
                break;
        }

    }

    close(sock_fd);

    return 0;
}
