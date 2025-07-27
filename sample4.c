// BIP-68(OP_CHECKSEQUENCEVERIFY) test

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wally_address.h"
#include "wally_crypto.h"
#include "wally_map.h"
#include "wally_script.h"

#include "btc_buf.h"
#include "btc_merkle.h"
#include "btc_p2tr_scriptpath.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
static const char ADDR_FAMILY[] = "bcrt";

/*
$ btcc 5 OP_CHECKSEQUENCEVERIFY OP_EQUAL
warning: ambiguous input 5 is interpreted as a numeric value; use OP_5 to force into opcode
55b287
*/
static const uint8_t SCRIPT[] = {
    0x55, 0xb2, 0x87,
};
static const uint8_t REDEEM_SCRIPT[] = {
    0x05,
};

static const uint8_t INTERNAL_PUBKEY[] = {
    0x92, 0x4c, 0x16, 0x3b, 0x38, 0x5a, 0xf7, 0x09,
    0x34, 0x40, 0x18, 0x4a, 0xf6, 0xfd, 0x62, 0x44,
    0x93, 0x6d, 0x12, 0x88, 0xcb, 0xb4, 0x1c, 0xc3,
    0x81, 0x22, 0x86, 0xd3, 0xf8, 0x3a, 0x33, 0x29,
};

// outpoint txhash(not txid)
#define OUTPOINT_TXHASH { \
    0x7b, 0x17, 0x18, 0x9a, 0xf8, 0x16, 0x26, 0x3d,\
    0xb1, 0xd2, 0xea, 0x5b, 0x6a, 0xd4, 0xd6, 0xce,\
    0x68, 0x08, 0xe4, 0x9a, 0xd9, 0x6c, 0x5d, 0x63,\
    0x9f, 0x66, 0xc7, 0xd2, 0x22, 0xd8, 0xa1, 0x72,\
}
static const uint32_t OUTPOINT_INDEX = 1;
static const uint32_t SEQUENCE = 5;
static const char OUTADDR[] = "bcrt1q6ytggc6fyaphzkr89yghca9l9fra2vgw7mtlen";
static const uint64_t OUT_AMOUNT = 15000UL;
static const uint32_t LOCKTIME = 0;

static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void sample4(void)
{
    int rc;

    // leaf script
    //      5 OP_CHECKSEQUENCEVERIFY
    //      OP_EQUAL
    btc_bufp_t leaf_script;
    btc_bufp_alloc(&leaf_script, sizeof(SCRIPT));
    btc_bufp_push(&leaf_script, SCRIPT, sizeof(SCRIPT));
    printf("script: ");
    dump(leaf_script.buf.data, leaf_script.pos);

    // leaf script hash
    btc_buf_t leaf_msg;
    btc_buf_alloc(&leaf_msg, leaf_script.pos + 2);
    leaf_msg.data[0] = 0xc0; // leaf version
    leaf_msg.data[1] = leaf_script.pos; // compact_size(script)
    memcpy(leaf_msg.data + 2, leaf_script.buf.data, leaf_script.pos);

    uint256_t leaf_hash;
    rc = btc_p2tr_sp_leafhash(leaf_hash.data, leaf_msg.data, leaf_msg.len);
    if (rc != WALLY_OK) {
        printf("error: wally_bip340_tagged_hash: %d\n", rc);
        return;
    }
    printf("tap leaf hash: ");
    dump(leaf_hash.data, sizeof(leaf_hash));

    btc_buf_free(&leaf_msg);

    // merkle root
    const uint256_t *leaves[1] = {
        &leaf_hash,
    };
    uint256_t merkle_root;
    rc = calc_merkle_root(&merkle_root, leaves, ARRAY_SIZE(leaves), btc_p2tr_merkle_merge);
    if (rc != 0) {
        printf("error: calc_merkle_root %d\n", rc);
        return;
    }
    printf("merkle root: ");
    dump(merkle_root.data, sizeof(merkle_root));

    uint8_t tweakXonlyPubKey[EC_XONLY_PUBLIC_KEY_LEN];
    uint8_t witnessProgram[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    char *address;
    int parity;
    rc = btc_p2tr_sp_tweak_pubkey(
        tweakXonlyPubKey,
        witnessProgram,
        &address,
        &parity,
        INTERNAL_PUBKEY,
        merkle_root.data,
        ADDR_FAMILY
    );
    printf("tweak pubkey: ");
    dump(tweakXonlyPubKey, sizeof(tweakXonlyPubKey));
    printf("parity: %d\n", parity);
    printf("witness program: ");
    dump(witnessProgram, sizeof(witnessProgram));
    printf("address: %s\n", address);

    wally_free_string(address);

    struct wally_tx *tx = NULL;

    // create sighash, sig and wally_tx
    rc = wally_tx_init_alloc(
        2, // version
        LOCKTIME, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        return;
    }

    const struct wally_tx_input TX_INPUT = {
        .txhash = OUTPOINT_TXHASH,
        .index = OUTPOINT_INDEX,
        .sequence = SEQUENCE,
        // no scriptSig
        .script = NULL,
        .script_len = 0,
        // "witness" will be set later
        .witness = NULL,
        .features = 0,
    };
    rc = wally_tx_add_input(tx, &TX_INPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        return;
    }

    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(
        OUTADDR,
        ADDR_FAMILY,
        0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        return;
    }
    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = OUT_AMOUNT,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx, &TX_OUTPUT);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_output fail: %d\n", rc);
        return;
    }

    struct wally_map *scriptPubKeys;
    rc = wally_map_init_alloc(1, NULL, &scriptPubKeys);
    if (rc != WALLY_OK) {
        printf("error: wally_map_init_alloc fail: %d\n", rc);
        return;
    }
    rc = wally_map_add_integer(
        scriptPubKeys,
        0, // key
        witnessProgram, sizeof(witnessProgram));
    if (rc != WALLY_OK) {
        printf("error: wally_map_add_integer fail: %d\n", rc);
        return;
    }

    struct wally_tx_witness_stack *wit_stack;
    rc = wally_tx_witness_stack_init_alloc(3, &wit_stack);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_init_alloc fail: %d\n", rc);
        return;
    }

    // [0] 155
    rc = wally_tx_witness_stack_add(wit_stack, REDEEM_SCRIPT, sizeof(REDEEM_SCRIPT));
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[0] fail: %d\n", rc);
        return;
    }
    // [1] leaf script
    rc = wally_tx_witness_stack_add(wit_stack, leaf_script.buf.data, leaf_script.pos);
    btc_bufp_free(&leaf_script);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[1] fail: %d\n", rc);
        return;
    }
    // [2] control block
    btc_bufp_t ctrl_block;
    btc_bufp_alloc(&ctrl_block, 1 + EC_XONLY_PUBLIC_KEY_LEN);
    btc_bufp_push1(&ctrl_block, 0xc0 + parity);
    btc_bufp_push(&ctrl_block, INTERNAL_PUBKEY, sizeof(INTERNAL_PUBKEY));
    rc = wally_tx_witness_stack_add(wit_stack, ctrl_block.buf.data, ctrl_block.pos);
    btc_bufp_free(&ctrl_block);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[1] fail: %d\n", rc);
        return;
    }
    // set witness to input
    rc = wally_tx_set_input_witness(tx, 0, wit_stack);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_set_input_witness fail: %d\n", rc);
        return;
    }
    wally_tx_witness_stack_free(wit_stack);

    uint8_t txData[1024];
    size_t txLen = 0;
    rc = wally_tx_to_bytes(
        tx,
        WALLY_TX_FLAG_USE_WITNESS,
        txData, sizeof(txData), &txLen);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_to_bytes fail: %d\n", rc);
        return;
    }
    printf("tx: ");
    dump(txData, txLen);

    wally_tx_free(tx);
}
