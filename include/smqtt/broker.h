#ifndef BROKER_H
#define BROKER_H
#include <stdint.h>
#include <sodium.h>

struct Client_Context {
    uint16_t client_uid;
    int fd;
    int connected;
    int max_qos;
    struct Client_Context *next;
};

struct Topic_Context {
    char *topic_name;
    struct Client_Context *head;
};

int smqtt_broker_loop();

// int smqtt_poll();

int smqtt_bind();
int smqtt_listen();
int smqtt_accept();
int smqtt_broker_handshake(int client_fd,
                    unsigned char rx[],
                    unsigned char tx[],
                    const unsigned char server_pk[],
                    const unsigned char server_sk[]);

// int smqtt_connack();
// int smqtt_suback();
// int smqtt_unsuback();
// int smqtt_puback();
// int smqtt_broadcast();

// int smqtt_handle_client_packets();


#endif //BROKER_H
