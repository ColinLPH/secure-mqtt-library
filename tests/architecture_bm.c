#include <sodium.h>
#include <stdio.h>
#include <time.h>

// Payload Constants
const size_t SIZE_IOT      = 100;      // Typical MQTT sensor update
const size_t SIZE_STANDARD = 2048;     // 2 KB
const size_t SIZE_LARGE    = 10240;    // 10 KB
const size_t SIZE_BULK     = 102400;   // 100 KB

// Mocking the extra work a TLS stack does (Record header parsing, state checks)
void fake_tls_overhead() {
    volatile int overhead = 0;
    for(int i=0; i<50; i++) overhead += i; // Simulate state machine cycles
}

void compare_architectures(size_t size) {
    unsigned char key[32], nonce[24], payload[size], out[size+16];
    randombytes_buf(payload, size);
    randombytes_buf(key, 32);
    
    struct timespec start, end;
    int iters = 1000000;

    // --- TEST 1: RAW XChaCha (Your Project) ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<iters; i++) {
        unsigned long long clen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(out, &clen, payload, size, NULL, 0, NULL, nonce, key);
        sodium_increment(nonce, 24);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_xc = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    // --- TEST 2: SIMULATED TLS (ChaCha20 + Protocol Logic) ---
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<iters; i++) {
        fake_tls_overhead(); // Simulate the protocol overhead
        unsigned long long clen;
        // Using standard IETF ChaCha20 (as TLS does)
        crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, payload, size, NULL, 0, NULL, nonce, key);
        sodium_increment(nonce, 12); // TLS uses 12-byte nonces
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_tls = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Size: %zu B\n", size);
    printf("  XChaCha (Raw): %.4f s\n", time_xc);
    printf("  TLS (Simulated): %.4f s\n", time_tls);
    printf("  Improvement: %.1f%%\n\n", ((time_tls - time_xc) / time_tls) * 100);
}

int main() {
    int ret = sodium_init();
    if (ret < 0)
    {
        printf("sodium init failed\n");
        return 0;
    }
    compare_architectures(SIZE_IOT);  // IoT Size
    compare_architectures(SIZE_STANDARD); // Standard Size
    compare_architectures(SIZE_LARGE);
    compare_architectures(SIZE_BULK);
    return 0;
}