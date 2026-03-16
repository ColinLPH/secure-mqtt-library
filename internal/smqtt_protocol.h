#ifndef SMQTT_PROTOCOL_H
#define SMQTT_PROTOCOL_H

#define PROTOCOL_NAME "SMQTT"
#define PROTOCOL_VERSION 1

/* Message types */
#define CMD_RESERVED 0x00U
#define CMD_CONNECT 0x10U
#define CMD_CONNACK 0x20U
#define CMD_PUBLISH 0x30U
#define CMD_PUBACK 0x40U
#define CMD_PUBREC 0x50U
#define CMD_PUBREL 0x60U
#define CMD_PUBCOMP 0x70U
#define CMD_SUBSCRIBE 0x80U
#define CMD_SUBACK 0x90U
#define CMD_UNSUBSCRIBE 0xA0U
#define CMD_UNSUBACK 0xB0U
#define CMD_PINGREQ 0xC0U
#define CMD_PINGRESP 0xD0U
#define CMD_DISCONNECT 0xE0U
#define CMD_AUTH 0xF0U
#include <stdint.h>

/**
 * Values:
 *  CONNACK_ACCEPTED - 0
 *  CONNACK_REFUSED_PROTOCOL_VERSION - 1
 *  CONNACK_REFUSED_IDENTIFIER_REJECTED - 2
 *  CONNACK_REFUSED_SERVER_UNAVAILABLE - 3
 *  CONNACK_REFUSED_BAD_USERNAME_PASSWORD - 4
 *  CONNACK_REFUSED_NOT_AUTHORIZED - 5
 */
enum smqtt_connack_codes {
	CONNACK_ACCEPTED = 0,
	CONNACK_REFUSED_PROTOCOL_VERSION = 1,
	CONNACK_REFUSED_IDENTIFIER_REJECTED = 2,
	CONNACK_REFUSED_SERVER_UNAVAILABLE = 3,
	CONNACK_REFUSED_BAD_USERNAME_PASSWORD = 4,
	CONNACK_REFUSED_NOT_AUTHORIZED = 5,
};

typedef struct smqtt_pkt {
	uint8_t *payload;
	struct smqtt_pkt *next;
	uint64_t seq_num;

	uint32_t remaining_len_multi;
	uint32_t remaining_len;
	uint32_t pkt_total_len;
	uint32_t bytes_to_process;
	uint32_t payload_pos;

	uint8_t fixed_header;
	uint8_t remaining_len_count;
} smqtt_pkt;

#endif //SMQTT_PROTOCOL_H
