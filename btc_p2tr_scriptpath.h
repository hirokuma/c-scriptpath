#ifndef BTC_P2TR_SCRIPTPATH_H
#define BTC_P2TR_SCRIPTPATH_H

#include "wally_script.h"

#include "btc_types.h"

int btc_p2tr_merkle_merge(
    uint256_t *merged,
    const uint256_t *p1,
    const uint256_t *p2);

int btc_p2tr_sp_leafhash(
    uint8_t hash[SHA256_LEN],
    const uint8_t *script, size_t script_len);

int btc_p2tr_sp_tweak_pubkey(
    uint8_t pubkey[EC_XONLY_PUBLIC_KEY_LEN],
    uint8_t witprog[WALLY_SCRIPTPUBKEY_P2TR_LEN],
    char **address,
    int *parity,
    const uint8_t intr_pubkey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t merkle_root[SHA256_LEN],
    const char *addr_family);

int btc_p2tr_sp_sig(
    uint8_t *sig, size_t sig_len,
    uint32_t index,
    const struct wally_tx *tx,
    const struct wally_map *prevScriptPubKeys,
    const uint64_t values[], size_t num_values,
    const uint8_t *script, size_t script_len,
    uint8_t sighash_type,
    const uint8_t privKey[EC_PRIVATE_KEY_LEN]);

#endif /* BTC_P2TR_SCRIPTPATH_H */
