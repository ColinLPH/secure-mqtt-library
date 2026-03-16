#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "smqtt_aead.h"
#include "smqtt/broker.h"
#include "smqtt/common.h"

int smqtt_bind(int fd, int port, char *broker_ip) {
	struct sockaddr_in ipv4_addr = {0};

	if (broker_ip != NULL) {
	    if(inet_pton(AF_INET, broker_ip, &ipv4_addr.sin_addr) != 1) {
        	return -1;
    	}
	} else {
    	ipv4_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}


	ipv4_addr.sin_family = AF_INET;
	ipv4_addr.sin_port = htons(port);

	if(bind(fd, (struct sockaddr *)&ipv4_addr, sizeof(ipv4_addr)) != 0){
		return -1;
	}

	return 0;
}

int smqtt_listen(int fd, int backlog) {
	return listen(fd, backlog);
}

int smqtt_accept(int listen_fd, struct sockaddr_in *client_addr) {
    int client_fd;

    if (client_addr != NULL) {
        socklen_t addrlen = sizeof(struct sockaddr_in);
        client_fd = accept(listen_fd, (struct sockaddr *)client_addr, &addrlen);
    } else {
        client_fd = accept(listen_fd, NULL, NULL);
    }

    return client_fd;
}

int smqtt_broker_handshake(int client_fd,
                    unsigned char rx[],
                    unsigned char tx[],
                    const unsigned char server_pk[],
                    const unsigned char server_sk[]) {
   	// Send server public key
    send__all(client_fd, server_pk, crypto_kx_PUBLICKEYBYTES);
    print_hex("Server PK sent", server_pk, crypto_kx_PUBLICKEYBYTES);

    // Receive client public key
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    recv__all(client_fd, client_pk, sizeof(client_pk));
    print_hex("Client PK received", client_pk, sizeof(client_pk));

    // Derive session keys
    if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk) != 0) {
        fprintf(stderr, "Server session key derivation failed!\n");
        return -1;
    }

	return 0;
}

int smoqer_main_loop() {
    return 0;
}
