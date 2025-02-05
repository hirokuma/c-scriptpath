#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "btc_merkle.h"

static int _merge(uint256_t *merged, const uint256_t *p1, const uint256_t *p2)
{
    uint8_t buf[SHA256_LEN * 2];
    memcpy(buf, p1->data, SHA256_LEN);
    memcpy(buf + SHA256_LEN, p2->data, SHA256_LEN);
    int rc = wally_bip340_tagged_hash(
        buf, sizeof(buf),
        "TapBranch",
        merged->data, sizeof(uint256_t));
    return rc;
}

static uint256_t *_mtree(uint256_t *in, uint32_t *cnt, int keep)
{
    uint32_t prev_cnt = *cnt;

#warning leftが小さくなるようにソートが必要
    uint256_t *out = (uint256_t *)malloc(sizeof(uint256_t) * (*cnt + 1) / 2);
    *cnt /= 2;
    for (uint32_t i = 0; i < *cnt; i++) {
        if(_merge(&out[i], &in[2 * i], &in[2 * i + 1]) != WALLY_OK) {
            free(out);
            return NULL;
        }
    }
    if (prev_cnt & 1) {
        // odd
        _merge(&out[*cnt], &in[*cnt * 2], &in[*cnt * 2]);
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
    uint32_t cnt)
{
    int height = (int)ceil(log2(1.0 * cnt));
    uint256_t *p = (uint256_t *)malloc(SHA256_LEN * cnt);
    for (int i = 0; i < cnt; i++) {
        memcpy(p[i].data, leaves[i]->data, SHA256_LEN);
    }
    int keep = 1;
    for (int i = 0; i < height; i++) {
        p = _mtree(p, &cnt, keep);
        if (p == NULL) {
            free(p);
            return 1;
        }
        keep = 0;
    }
    memcpy(root->data, p[0].data, SHA256_LEN);
    free(p);

    return 0;
}
