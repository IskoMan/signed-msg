/* SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104). No dependencies. */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32
#define SHA256_BLOCK 64

typedef struct {
    uint32_t h[8];
    uint64_t bytes;          /* total bytes hashed so far */
    uint8_t buf[SHA256_BLOCK];
    size_t buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_LEN]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_LEN]);

typedef struct {
    sha256_ctx inner;
    uint8_t okey[SHA256_BLOCK];  /* key ^ opad, kept for the outer hash */
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *c, const void *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx *c, const void *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[SHA256_LEN]);
void hmac_sha256(const void *key, size_t key_len, const void *data, size_t len,
                 uint8_t out[SHA256_LEN]);

#endif
