#include <arpa/inet.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "smqtt_aead.h"
#include "smqtt/client.h"
#include "smqtt/common.h"

int smqtt_connect(int sock_fd, const char* server_ip , int port) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);
    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
		return -1;
	}

    return 0;
}

static int verify_server_pk(const unsigned char *server_pk, const unsigned char *pinned_hash) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, server_pk, crypto_kx_PUBLICKEYBYTES);

    print_hex("Received Server PK SHA-256", hash, sizeof(hash));

    if (memcmp(hash, pinned_hash, crypto_hash_sha256_BYTES) != 0) {
        printf("Server public key hash mismatch! Aborting.\n");
        return 0;
    }
    return 1;
}

int smqtt_client_handshake(int sock,
                    unsigned char rx[],
                    unsigned char tx[],
                    const unsigned char *pinned_hash) {
    // Receive server public key
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    recv__all(sock, server_pk, sizeof(server_pk));
    print_hex("Server PK", server_pk, sizeof(server_pk));

    if (!verify_server_pk(server_pk, pinned_hash)) return -1;

    // Generate client keypair
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    // Send client public key
    send__all(sock, client_pk, sizeof(client_pk));
    print_hex("Client PK", client_pk, sizeof(client_pk));

    // Derive session keys
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        fprintf(stderr, "Client session key derivation failed!\n");
        return -1;
    }

	return 0;
}

