#include <stdlib.h>
#include <string.h>

#include <endian.h>

#include "btc_buf.h"

#define SZ_PUSH     (1024)      /// push時にreallocする際の増分

void btc_buf_alloc(btc_buf_t *buf, size_t len)
{
    buf->len = len;
    if (len > 0) {
        buf->data = (uint8_t *)malloc(len);
    } else {
        buf->data = 0;
    }
}

void btc_buf_trunc(btc_buf_t *buf, size_t len)
{
    if (len < buf->len) {
        // shrink
        buf->len = len;
        buf->data = (uint8_t *)realloc(buf->data, len);
    }
}

void btc_buf_free(btc_buf_t *buf)
{
    if (buf->data) {
        free(buf->data);
        buf->data = 0;
        buf->len = 0;
    }
}

// pBufSrcを使用してbtc_bufp_tを初期化する。
// pBufSrcの内容はfreeされないよう。
void btc_bufp_set(btc_bufp_t *bufp, btc_buf_t *src)
{
    bufp->buf = *src;
    bufp->pos = 0;
    src->data = 0;
    src->len = 0;
}

void btc_bufp_alloc(btc_bufp_t *bufp, size_t len)
{
    bufp->pos = 0;
    btc_buf_alloc(&bufp->buf, len);
}

void btc_bufp_push(btc_bufp_t *bufp, const uint8_t *data, size_t len)
{
    if (bufp->buf.len < bufp->pos + len) {
        bufp->buf.len += SZ_PUSH;
        bufp->buf.data = (uint8_t *)realloc(bufp->buf.data, bufp->buf.len);
    }
    memcpy(bufp->buf.data + bufp->pos, data, len);
    bufp->pos += len;
}

void btc_bufp_push1(btc_bufp_t *bufp, uint8_t data)
{
    btc_bufp_push(bufp, (const uint8_t *)&data, sizeof(data));
}

void btc_bufp_push_uint16le(btc_bufp_t *bufp, uint16_t val)
{
    val = htole16(val);
    btc_bufp_push(bufp, (const uint8_t *)&val, sizeof(val));
}

void btc_bufp_push_uint32le(btc_bufp_t *bufp, uint32_t val)
{
    val = htole32(val);
    btc_bufp_push(bufp, (const uint8_t *)&val, sizeof(val));
}

void btc_bufp_push_uint64le(btc_bufp_t *bufp, uint64_t val)
{
    val = htole64(val);
    btc_bufp_push(bufp, (const uint8_t *)&val, sizeof(val));
}

void btc_bufp_trunc(btc_bufp_t *bufp)
{
    btc_buf_trunc(&bufp->buf, bufp->pos);
}

void btc_bufp_free(btc_bufp_t *bufp)
{
    bufp->pos = 0;
    btc_buf_free(&bufp->buf);
}
