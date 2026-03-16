#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>

typedef struct smqtt_pkt smqtt_pkt;
typedef struct crypto_info crypto_info;

int smqtt_socket(void);
int smqtt_send_packet(smqtt_pkt *packet, crypto_info *crypt, int dest_fd);

void print_hex(const char *label, const unsigned char *buf, size_t len);
ssize_t recv__all(int sock, unsigned char *buf, size_t len);
ssize_t send__all(int sock, const unsigned char *buf, size_t len);

#endif // COMMON_H
