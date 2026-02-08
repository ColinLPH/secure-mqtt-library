#ifndef SMQTT_BROKER_H
#define SMQTT_BROKER_H

int smqtt_bind();
int smqtt_listen();
int smqtt_accept();

int smqtt_connack();
int smqtt_suback();
int smqtt_unsuback();
int smqtt_puback();
int smqtt_broadcast();

int smqtt_handle_packets();


#endif //SMQTT_BROKER_H
