#ifndef BTC_MERKLE_H
#define BTC_MERKLE_H

#include "btc_types.h"

int calc_merkle_root(
    uint256_t *root,
    const uint256_t *leaves[],
    uint32_t cnt);

#endif /* BTC_MERKLE_H */
