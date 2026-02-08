#ifndef SMQTT_COMMON_H
#define SMQTT_COMMON_H

#include <sys/socket.h>
#include <netinet/in.h>

// void print_hex(const char *label, const unsigned char *buf, size_t len);
ssize_t send_all(int sock, const unsigned char *buf, size_t len);
ssize_t recv_all(int sock, unsigned char *buf, size_t len);

int smqtt_socket();

int smqtt_send(smqtt_pkt *packet, );
int smqtt_recv();

#endif // SMQTT_COMMON
