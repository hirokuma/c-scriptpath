#ifndef BTC_MERKLE_H
#define BTC_MERKLE_H

#include "btc_types.h"

// merge_func: Returns 0 on success, anything else on failure.
int calc_merkle_root(
    uint256_t *root,
    const uint256_t *leaves[],
    uint32_t cnt,
    int (*merge_func)(uint256_t *merged, const uint256_t *p1, const uint256_t *p2));

#endif /* BTC_MERKLE_H */
