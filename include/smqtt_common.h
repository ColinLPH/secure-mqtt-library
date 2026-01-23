#ifndef SMQTT_COMMON_H
#define SMQTT_COMMON_H

#include <arpa/inet.h>

void print_hex(const char *label, const unsigned char *buf, size_t len);
ssize_t send_all(int sock, const unsigned char *buf, size_t len);
ssize_t recv_all(int sock, unsigned char *buf, size_t len);

#endif // SMQTT_COMMON
