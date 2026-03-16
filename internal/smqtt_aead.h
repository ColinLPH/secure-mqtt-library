#ifndef SMQTT_AEAD_H
#define SMQTT_AEAD_H

#include <sodium.h>

#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG_SIZE   crypto_aead_xchacha20poly1305_ietf_ABYTES

typedef struct crypto_info {
    uint8_t sub_pk[crypto_kx_PUBLICKEYBYTES];

    uint8_t decrypt_key[crypto_kx_SESSIONKEYBYTES];
    uint8_t encrypt_key[crypto_kx_SESSIONKEYBYTES];

    uint64_t session_start;
} crypto_info;

int encrypt_payload(const uint8_t *plaintext, size_t pt_len,
    const uint8_t *key, uint8_t *nonce, uint8_t *ciphertext);

int decrypt_payload(const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext);

void derive_session_keys(
        unsigned char rx[], unsigned char tx[],
        unsigned char client_pk[], unsigned char client_sk[],
        const unsigned char server_pk[]);


#endif //SMQTT_AEAD_H
