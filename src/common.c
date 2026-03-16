#include "smqtt/common.h"
#include "smqtt_aead.h"
#include "smqtt_protocol.h"

#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int smqtt_socket(void){
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    return fd;
}

/**
int smqtt_send_packet(smqtt_pkt *packet, crypto_info *crypt, int dest_fd) {
    uint8_t msg_nonce[NONCE_SIZE];
    uint8_t *cipher_buf;
    uint32_t cipher_len;

    cipher_len = packet->pkt_total_len + TAG_SIZE;
    randombytes_buf(msg_nonce, NONCE_SIZE);
    cipher_buf = malloc(cipher_len * sizeof(uint8_t));
    if (!cipher_buf) {
        perror("malloc");
        return -1;
    }

    if (encrypt_payload(packet->payload, packet->pkt_total_len,
        crypt->encrypt_key, msg_nonce, cipher_buf) == -1) {
        perror("encrypt_payload failed");
        free(cipher_buf);
        return -1;
    }

    uint32_t net_len = htonl(cipher_len);

    // send net len
    if (send(dest_fd, &net_len, sizeof net_len, 0) == -1) {
        perror("send net_len failed");
        free(cipher_buf);
        return -1;
    }

    // send nonce
    if (send(dest_fd, msg_nonce, NONCE_SIZE, 0) == -1) {
        perror("send msg_nonce failed");
        free(cipher_buf);
        return -1;
    }

    // send ct
    if (send(dest_fd, cipher_buf, cipher_len, 0) == -1) {
        perror("send cipher failed");
        free(cipher_buf);
        return -1;
    }

    free(cipher_buf);

    return 0;
}
*/

//-------------------------------------------------------------
// Utils
//-------------------------------------------------------------

void print_hex(const char *label, const unsigned char *buf, size_t len) {
     printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

ssize_t send__all(int sock, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv__all(int sock, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(sock, buf + recvd, len - recvd, 0);
        if (n <= 0) return -1;
        recvd += n;
    }
    return recvd;
}

