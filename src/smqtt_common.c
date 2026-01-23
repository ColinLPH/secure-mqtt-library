#include "smqtt_common.h"

//-------------------------------------------------------------
// Utils
//-------------------------------------------------------------

void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

ssize_t send_all(int sock, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

ssize_t recv_all(int sock, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(sock, buf + recvd, len - recvd, 0);
        if (n <= 0) return -1;
        recvd += n;
    }
    return recvd;
}
