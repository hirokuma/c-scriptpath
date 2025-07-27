#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "btc_merkle.h"

static uint256_t *_mtree(
    uint256_t *in,
    uint32_t *cnt,
    int keep,
    int (*merge_func)(uint256_t *merged, const uint256_t *p1, const uint256_t *p2))
{
    uint32_t prev_cnt = *cnt;

    uint256_t *out = (uint256_t *)malloc(sizeof(uint256_t) * (*cnt + 1) / 2);
    *cnt /= 2;
    for (uint32_t i = 0; i < *cnt; i++) {
        if (merge_func(&out[i], &in[2 * i], &in[2 * i + 1]) != WALLY_OK) {
            free(out);
            return NULL;
        }
    }
    if (prev_cnt & 1) {
        // odd
        if (merge_func(&out[*cnt], &in[*cnt * 2], &in[*cnt * 2])) {
            free(out);
            return NULL;
        }
        (*cnt)++;
    }
    if (!keep) {
        free(in);
    }
    return out;
}

int calc_merkle_root(
    uint256_t *root,
    const uint256_t *leaves[],
    uint32_t cnt,
    int (*merge_func)(uint256_t *merged, const uint256_t *p1, const uint256_t *p2))
{
    int height = (int)ceil(log2(1.0 * cnt));
    uint256_t *p = (uint256_t *)malloc(SHA256_LEN * cnt);
    uint256_t *in = p;
    for (int i = 0; i < cnt; i++) {
        memcpy(p[i].data, leaves[i]->data, SHA256_LEN);
    }
    int keep = 1;
    for (int i = 0; i < height; i++) {
        p = _mtree(p, &cnt, keep, merge_func);
        if (p == NULL) {
            free(p);
            return 1;
        }
        keep = 0;
    }
    memcpy(root->data, p[0].data, SHA256_LEN);
    free(in);

    return 0;
}
