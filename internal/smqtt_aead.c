#include "smqtt_aead.h"

int encrypt_payload( const uint8_t *plaintext, size_t pt_len,
    const uint8_t *key, uint8_t *nonce, uint8_t *ciphertext) {

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, NULL, plaintext, pt_len,
        NULL, 0, NULL, nonce, key) == -1) {
        perror("crypto_aead_xchacha20poly1305_ietf_encrypt");
        return -1;
    }

    return 0;
}

int decrypt_payload(const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext) {

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, NULL,
        NULL,
        ciphertext, ct_len,
        NULL, 0,
        nonce, key) == -1) {

        perror("crypto_aead_xchacha20poly1305_ietf_decrypt");
        return -1;
        }

    return 0;
}

void derive_session_keys(
        unsigned char rx[], unsigned char tx[],
        unsigned char client_pk[], unsigned char client_sk[],
        const unsigned char server_pk[])
{
    if (crypto_kx_client_session_keys(rx, tx,
                                      client_pk, client_sk,
                                      server_pk) != 0)
    {
        printf("Failed to derive session keys\n");
        exit(1);
    }
}
