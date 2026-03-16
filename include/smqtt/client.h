#ifndef CLIENT_H
#define CLIENT_H

int smqtt_connect();

/**
int smqtt_subscribe();
int smqtt_unsubscribe();
int smqtt_publish();
*/
int smqtt_client_handshake(int sock,
                    unsigned char rx[],
                    unsigned char tx[],
                    const unsigned char *pinned_hash);

#endif //CLIENT_H
