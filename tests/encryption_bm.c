#define _POSIX_C_SOURCE 200809L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WARMUP_ITERATIONS 10000

// Payload Constants
const size_t SIZE_IOT      = 100;      
const size_t SIZE_STANDARD = 2048;     
const size_t SIZE_LARGE    = 10240;    
const size_t SIZE_BULK     = 102400;   

typedef int (*encrypt_fn)(unsigned char *, unsigned long long *, const unsigned char *, 
                          unsigned long long, const unsigned char *, unsigned long long, 
                          const unsigned char *, const unsigned char *, const unsigned char *);

// ---------------------------------------------------------
// Benchmarking Engine
// ---------------------------------------------------------
void run_bench(const char* label, const char* cipher_name, encrypt_fn func, 
               size_t payload_size, size_t nonce_size, size_t key_size, int iterations) {
    
    unsigned char *payload = malloc(payload_size);
    unsigned char *ciphertext = malloc(payload_size + 16); // 16 for Auth Tag
    unsigned char *nonce = malloc(nonce_size);
    unsigned char *key = malloc(key_size);
    
    randombytes_buf(payload, payload_size);
    randombytes_buf(key, key_size);
    memset(nonce, 0, nonce_size);

    // Warm-up
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        unsigned long long clen;
        func(ciphertext, &clen, payload, payload_size, NULL, 0, NULL, nonce, key);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < iterations; i++) {
        unsigned long long clen;
        func(ciphertext, &clen, payload, payload_size, NULL, 0, NULL, nonce, key);
        sodium_increment(nonce, nonce_size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double total_s = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double avg_ns = (total_s * 1e9) / iterations;
    double throughput_mib = ((double)payload_size * iterations) / (1024 * 1024 * total_s);
    double gbps = ((double)payload_size * iterations * 8) / (total_s * 1e9);

    printf("| %-9s | %-16s | %8zu | %10.1f ns | %10.2f MiB/s | %6.2f |\n", 
           label, cipher_name, payload_size, avg_ns, throughput_mib, gbps);

    free(payload); free(ciphertext); free(nonce); free(key);
}

int main(void) {
    if (sodium_init() < 0) return 1;

    printf("Comparison: TLS 1.3 Approved Suites vs. Custom XChaCha Implementation\n");
    printf("==========================================================================================\n");
    printf("| Category  | Cipher Suite     | Size (B) | Avg Latency | Throughput    | Gbps   |\n");
    printf("|-----------|------------------|----------|-------------|---------------|--------|\n");

    size_t sizes[] = { SIZE_IOT, SIZE_STANDARD, SIZE_LARGE, SIZE_BULK };
    const char* labels[] = { "IoT", "Standard", "Large", "Bulk" };
    
    for (int i = 0; i < 4; i++) {
        int iters = (sizes[i] > 20000) ? 100000 : 1000000;

        // 1. Your Project: XChaCha20-Poly1305 (192-bit nonce)
        run_bench(labels[i], "XChaCha20-P1305", crypto_aead_xchacha20poly1305_ietf_encrypt, 
                  sizes[i], 24, 32, iters);

        // 2. TLS 1.3 Fallback: ChaCha20-Poly1305 (96-bit nonce)
        run_bench(labels[i], "ChaCha20-P1305", crypto_aead_chacha20poly1305_ietf_encrypt, 
                  sizes[i], 12, 32, iters);

        // 3. TLS 1.3 Primary: AES-256-GCM (Requires Hardware)
        if (crypto_aead_aes256gcm_is_available()) {
            run_bench(labels[i], "AES-256-GCM", crypto_aead_aes256gcm_encrypt, 
                      sizes[i], 12, 32, iters);
        }
        printf("|-----------|------------------|----------|-------------|---------------|--------|\n");
    }

    return 0;
}