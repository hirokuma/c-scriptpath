#ifndef BTC_TYPES_H
#define BTC_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "wally_crypto.h"

typedef struct {
    uint8_t data[SHA256_LEN];
} uint256_t;

/////////////////
// well use macro
/////////////////

#define BTC_ARRAY_SIZE(a)   (sizeof(a) / sizeof(a[0]))

/////////////////
// little endian
/////////////////

static inline uint16_t btc_endian_pack_u16le(const uint8_t *pData) {
    return (uint16_t)(
        ((uint16_t)*pData) |
        ((uint16_t)*(pData + 1) << 8)
    );
}


static inline uint32_t btc_endian_pack_u32le(const uint8_t *pData) {
    return (uint32_t)(
        ((uint32_t)*pData)             |
        ((uint32_t)*(pData + 1) << 8)  |
        ((uint32_t)*(pData + 2) << 16) |
        ((uint32_t)*(pData + 3) << 24)
    );
}

static inline uint64_t btc_endian_pack_u64le(const uint8_t *pData) {
    return (uint64_t)(
        ((uint64_t)*pData)             |
        ((uint64_t)*(pData + 1) << 8 ) |
        ((uint64_t)*(pData + 2) << 16) |
        ((uint64_t)*(pData + 3) << 24) |
        ((uint64_t)*(pData + 4) << 32) |
        ((uint64_t)*(pData + 5) << 40) |
        ((uint64_t)*(pData + 6) << 48) |
        ((uint64_t)*(pData + 7) << 56)
    );
}

#endif /* BTC_TYPES_H */
