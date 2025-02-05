#include <string.h>

#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_script.h"

#include "btc_p2tr_scriptpath.h"
#include "btc_buf.h"

int btc_p2tr_sp_leafhash(
    uint8_t hash[SHA256_LEN],
    const uint8_t *script, size_t script_len)
{
    return wally_bip340_tagged_hash(
        script, script_len,
        "TapLeaf",
        hash, SHA256_LEN);
}

int btc_p2tr_sp_tweak_pubkey(
    uint8_t pubkey[EC_XONLY_PUBLIC_KEY_LEN],
    uint8_t witprog[WALLY_SCRIPTPUBKEY_P2TR_LEN],
    char **address,
    int *parity,
    const uint8_t intr_pubkey[EC_XONLY_PUBLIC_KEY_LEN],
    const uint8_t merkle_root[SHA256_LEN],
    const char *addr_family)
{
    uint8_t tweak_pubKey[EC_PUBLIC_KEY_LEN];
    int rc = wally_ec_public_key_bip341_tweak(
        intr_pubkey, EC_XONLY_PUBLIC_KEY_LEN,
        merkle_root, SHA256_LEN,
        0,
        tweak_pubKey, sizeof(tweak_pubKey));
    if (rc != WALLY_OK) {
        return rc;
    }
    memcpy(pubkey, tweak_pubKey + 1, EC_XONLY_PUBLIC_KEY_LEN);
    *parity = tweak_pubKey[0] == 0x03;

    size_t witprog_len = 0;
    rc = wally_witness_program_from_bytes_and_version(
        pubkey, EC_XONLY_PUBLIC_KEY_LEN,
        1,
        0,
        witprog, WALLY_SCRIPTPUBKEY_P2TR_LEN, &witprog_len);
    if (rc != WALLY_OK) {
        return rc;
    }
    if (witprog_len != WALLY_SCRIPTPUBKEY_P2TR_LEN) {
        return 1;
    }
    if (address && addr_family) {
        rc = wally_addr_segwit_from_bytes(
            witprog, WALLY_SCRIPTPUBKEY_P2TR_LEN,
            addr_family,
            0,
            address);
        if (rc != WALLY_OK) {
            return rc;
        }
    }
    return 0;
}

int btc_p2tr_sp_sig(
    uint8_t *sig, size_t sig_len,
    uint32_t index,
    const struct wally_tx *tx,
    const struct wally_map *prevScriptPubKeys,
    const uint64_t values[], size_t num_values,
    const uint8_t *script, size_t script_len,
    uint8_t sighash_type,
    const uint8_t privKey[EC_PRIVATE_KEY_LEN])
{
    if (sig_len < EC_SIGNATURE_LEN ||
            (sighash_type != WALLY_SIGHASH_DEFAULT && sig_len < EC_SIGNATURE_LEN + 1)) {
        return 1;
    }

    uint8_t sighash[EC_MESSAGE_HASH_LEN];
    int rc = wally_tx_get_btc_taproot_signature_hash(
        tx,
        index,
        prevScriptPubKeys,
        values, num_values,
        script,  script_len,
        0x00, // key version
        WALLY_NO_CODESEPARATOR, // codesep position
        NULL, 0, // annex
        sighash_type,
        0, // flags
        sighash, sizeof(sighash)
    );
    if (rc != WALLY_OK) {
        return rc;
    }

    rc = wally_ec_sig_from_bytes(
        privKey, EC_PRIVATE_KEY_LEN,
        sighash, sizeof(sighash),
        EC_FLAG_SCHNORR,
        sig, EC_SIGNATURE_LEN
    );
    if (rc != WALLY_OK) {
        return rc;
    }
    if (sighash_type != WALLY_SIGHASH_DEFAULT) {
        sig[EC_SIGNATURE_LEN] = sighash_type;
    }
    return 0;
}
