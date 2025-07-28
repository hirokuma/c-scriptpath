#ifndef BTC_BUF_H
#define BTC_BUF_H

#include <stdint.h>

typedef struct {
    size_t len;
    uint8_t *data;
} btc_buf_t;

#define BTC_BUF_INIT() {0, 0}

void btc_buf_alloc(btc_buf_t *buf, size_t len);
void btc_buf_trunc(btc_buf_t *buf, size_t len);
void btc_buf_free(btc_buf_t *buf);

typedef struct {
    btc_buf_t buf;
    uint32_t pos;
} btc_bufp_t;

#define BTC_BUFP_INIT() {BTC_BUF_INIT(), 0}

void btc_bufp_set(btc_bufp_t *bufp, btc_buf_t *src);
void btc_bufp_alloc(btc_bufp_t *bufp, size_t len);
void btc_bufp_push(btc_bufp_t *bufp, const uint8_t *data, size_t len);
void btc_bufp_push_array(btc_bufp_t *bufp, const uint8_t *data, size_t len);
void btc_bufp_push1(btc_bufp_t *bufp, uint8_t data);
void btc_bufp_push_uint16le(btc_bufp_t *bufp, uint16_t val);
void btc_bufp_push_uint32le(btc_bufp_t *bufp, uint32_t val);
void btc_bufp_push_uint64le(btc_bufp_t *bufp, uint64_t val);
void btc_bufp_trunc(btc_bufp_t *bufp);
void btc_bufp_free(btc_bufp_t *bufp);

#endif /* BTC_BUF_H */
