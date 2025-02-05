#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_map.h"
#include "libwally-core/include/wally_script.h"

#include "btc_buf.h"
#include "btc_merkle.h"
#include "btc_p2tr_scriptpath.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static const char ADDR_FAMILY[] = "bcrt";

// https://github.com/hirokuma/js-scriptpath/blob/a4222d84fcdbeec01e5e069f04db4a5e0ca48c2f/README.md#run

static const uint8_t INTERNAL_PUBKEY[] = {
    0x96, 0xcb, 0x99, 0x7b, 0x08, 0x4b, 0xdb, 0x0a,
    0xb8, 0x69, 0x7e, 0xa3, 0x68, 0x04, 0x51, 0x40,
    0x93, 0x12, 0x61, 0x3b, 0xca, 0xc4, 0x77, 0xde,
    0xc3, 0x92, 0x69, 0x6b, 0x99, 0xed, 0x5b, 0xad,
};

static const char ADDRESS[] = "bcrt1puu7sdsl7y5s7tdc3l5vx2dek5hmqnlu5tkl99tl4sf5x78nfuw3stzh7vk";
static const uint64_t PREV_AMOUNT = 100000UL;

// eef8bcfcef120786ffb9d2468946897dd1533011219fa54c03a82787e96bafbd:1
#define OUTPOINT_TXHASH { \
    0xbd, 0xaf, 0x6b, 0xe9, 0x87, 0x27, 0xa8, 0x03,\
    0x4c, 0xa5, 0x9f, 0x21, 0x11, 0x30, 0x53, 0xd1,\
    0x7d, 0x89, 0x46, 0x89, 0x46, 0xd2, 0xb9, 0xff,\
    0x86, 0x07, 0x12, 0xef, 0xfc, 0xbc, 0xf8, 0xee,\
}
static const uint32_t OUTPOINT_INDEX = 1;
static const uint32_t SEQUENCE = 0xffffffff;
static const char OUTADDR[] = "bcrt1qg5zcj5tat4pw0ks4m8wfkynyah5jj43cmuuwwu";
static const uint64_t OUT_AMOUNT = 99000UL;

static const uint8_t ALICE_PRIVKEY[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
};
static const uint8_t ALICE_PUBKEY[] = {
    0x7f, 0xa0, 0x33, 0x13, 0x5f, 0x9f, 0x09, 0x9d,
    0x24, 0x3a, 0xde, 0x11, 0xf8, 0xb9, 0x26, 0x5d,
    0x58, 0xa6, 0x31, 0x6e, 0x93, 0x0c, 0xe0, 0xcd,
    0x57, 0x82, 0x4e, 0xf9, 0x67, 0xbb, 0x62, 0x9d,
};
// static const uint8_t BOB_PRIVKEY[] = {
//     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01,
//     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01,
// };
static const uint8_t BOB_PUBKEY[] = {
    0x3d, 0xce, 0x6c, 0x62, 0x0f, 0xca, 0xbc, 0xfe,
    0xdc, 0x2c, 0xe2, 0xc4, 0x6f, 0xbd, 0x57, 0xea,
    0x71, 0x7d, 0xb2, 0x6d, 0xf3, 0x0a, 0xfc, 0x95,
    0x08, 0x2b, 0x2f, 0xdd, 0x67, 0xec, 0xd1, 0x6a,
};
static const uint8_t SIG[] = {
    0xa2, 0xe2, 0xa2, 0x7b, 0xff, 0x77, 0x27, 0x10,
    0x14, 0x74, 0xdd, 0xb8, 0x67, 0x46, 0x52, 0xfb,
    0x00, 0xc3, 0x17, 0x22, 0xb8, 0x1e, 0x9b, 0xa9,
    0xf0, 0xb2, 0x1d, 0x19, 0xcb, 0x58, 0xc3, 0x70,
    0x90, 0x9f, 0xfb, 0xf6, 0x42, 0xac, 0xb2, 0x75,
    0x38, 0xd0, 0x96, 0x7a, 0x19, 0x1f, 0x77, 0x9d,
    0xd4, 0x4d, 0xd7, 0xf7, 0xa5, 0x12, 0x08, 0x2c,
    0x49, 0xf1, 0xee, 0xa1, 0x39, 0x3e, 0x2e, 0xfe,
};

static const uint8_t TXDATA[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xbd,
    0xaf, 0x6b, 0xe9, 0x87, 0x27, 0xa8, 0x03, 0x4c,
    0xa5, 0x9f, 0x21, 0x11, 0x30, 0x53, 0xd1, 0x7d,
    0x89, 0x46, 0x89, 0x46, 0xd2, 0xb9, 0xff, 0x86,
    0x07, 0x12, 0xef, 0xfc, 0xbc, 0xf8, 0xee, 0x01,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x01, 0xb8, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x16, 0x00, 0x14, 0x45, 0x05, 0x89, 0x51,
    0x7d, 0x5d, 0x42, 0xe7, 0xda, 0x15, 0xd9, 0xdc,
    0x9b, 0x12, 0x64, 0xed, 0xe9, 0x29, 0x56, 0x38,
    0x03, 0x40, 0xa2, 0xe2, 0xa2, 0x7b, 0xff, 0x77,
    0x27, 0x10, 0x14, 0x74, 0xdd, 0xb8, 0x67, 0x46,
    0x52, 0xfb, 0x00, 0xc3, 0x17, 0x22, 0xb8, 0x1e,
    0x9b, 0xa9, 0xf0, 0xb2, 0x1d, 0x19, 0xcb, 0x58,
    0xc3, 0x70, 0x90, 0x9f, 0xfb, 0xf6, 0x42, 0xac,
    0xb2, 0x75, 0x38, 0xd0, 0x96, 0x7a, 0x19, 0x1f,
    0x77, 0x9d, 0xd4, 0x4d, 0xd7, 0xf7, 0xa5, 0x12,
    0x08, 0x2c, 0x49, 0xf1, 0xee, 0xa1, 0x39, 0x3e,
    0x2e, 0xfe, 0x22, 0x20, 0x7f, 0xa0, 0x33, 0x13,
    0x5f, 0x9f, 0x09, 0x9d, 0x24, 0x3a, 0xde, 0x11,
    0xf8, 0xb9, 0x26, 0x5d, 0x58, 0xa6, 0x31, 0x6e,
    0x93, 0x0c, 0xe0, 0xcd, 0x57, 0x82, 0x4e, 0xf9,
    0x67, 0xbb, 0x62, 0x9d, 0xac, 0x41, 0xc1, 0x96,
    0xcb, 0x99, 0x7b, 0x08, 0x4b, 0xdb, 0x0a, 0xb8,
    0x69, 0x7e, 0xa3, 0x68, 0x04, 0x51, 0x40, 0x93,
    0x12, 0x61, 0x3b, 0xca, 0xc4, 0x77, 0xde, 0xc3,
    0x92, 0x69, 0x6b, 0x99, 0xed, 0x5b, 0xad, 0x47,
    0xb0, 0x7e, 0xc5, 0xa8, 0x31, 0x97, 0x3b, 0x30,
    0xf6, 0x7f, 0x0d, 0xd2, 0x44, 0x9e, 0x8e, 0x14,
    0x55, 0xa3, 0x2a, 0x96, 0x75, 0x64, 0xa5, 0x6f,
    0x71, 0x51, 0x8f, 0x0a, 0x31, 0xbf, 0x28, 0x00,
    0x00, 0x00, 0x00,
};


static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void sample2(void)
{
    int rc;

    printf("internal pubkey: ");
    dump(INTERNAL_PUBKEY, sizeof(INTERNAL_PUBKEY));

    // leaf script(Alice)
    //      20 <alice_pubkey=7fa033135f9f099d243ade11f8b9265d58a6316e930ce0cd57824ef967bb629d>
    //      OP_CHECKSIG
    btc_bufp_t leaf_script_alice;
    btc_bufp_alloc(&leaf_script_alice, 50);
    btc_bufp_push1(&leaf_script_alice, sizeof(ALICE_PUBKEY));
    btc_bufp_push(&leaf_script_alice, ALICE_PUBKEY, sizeof(ALICE_PUBKEY));
    btc_bufp_push1(&leaf_script_alice, OP_CHECKSIG);
    btc_bufp_trunc(&leaf_script_alice);
    printf("Alice script: ");
    dump(leaf_script_alice.buf.data, leaf_script_alice.pos);

    // leaf script(Bob)
    //      20 <alice_pubkey=3dce6c620fcabcfedc2ce2c46fbd57ea717db26df30afc95082b2fdd67ecd16a>
    //      OP_CHECKSIG
    btc_bufp_t leaf_script_bob;
    btc_bufp_alloc(&leaf_script_bob, 50);
    btc_bufp_push1(&leaf_script_bob, sizeof(BOB_PUBKEY));
    btc_bufp_push(&leaf_script_bob, BOB_PUBKEY, sizeof(BOB_PUBKEY));
    btc_bufp_push1(&leaf_script_bob, OP_CHECKSIG);
    btc_bufp_trunc(&leaf_script_bob);
    printf("Bob script: ");
    dump(leaf_script_bob.buf.data, leaf_script_bob.pos);

    // leaf script hash
    uint256_t leaf_hash_alice;
    uint256_t leaf_hash_bob;
    btc_buf_t leaf_msg;
    btc_bufp_t *leaf_script;

    leaf_script = &leaf_script_alice;
    btc_buf_alloc(&leaf_msg, leaf_script->pos + 2);
    leaf_msg.data[0] = 0xc0; // leaf version
    leaf_msg.data[1] = leaf_script->pos; // compact_size(script)
    memcpy(leaf_msg.data + 2, leaf_script->buf.data, leaf_script->pos);

    rc = btc_p2tr_sp_leafhash(leaf_hash_alice.data, leaf_msg.data, leaf_msg.len);
    if (rc != WALLY_OK) {
        printf("error: wally_bip340_tagged_hash: %d\n", rc);
        return;
    }
    printf("Alice leaf hash: ");
    dump(leaf_hash_alice.data, sizeof(leaf_hash_alice));
    btc_buf_free(&leaf_msg);

    leaf_script = &leaf_script_bob;
    btc_buf_alloc(&leaf_msg, leaf_script->pos + 2);
    leaf_msg.data[0] = 0xc0; // leaf version
    leaf_msg.data[1] = leaf_script->pos; // compact_size(script)
    memcpy(leaf_msg.data + 2, leaf_script->buf.data, leaf_script->pos);

    rc = btc_p2tr_sp_leafhash(leaf_hash_bob.data, leaf_msg.data, leaf_msg.len);
    if (rc != WALLY_OK) {
        printf("error: wally_bip340_tagged_hash: %d\n", rc);
        return;
    }
    printf("Bob leaf hash: ");
    dump(leaf_hash_bob.data, sizeof(leaf_hash_bob));
    btc_buf_free(&leaf_msg);

    // merkle root
    const uint256_t *leaves[2] = {
        &leaf_hash_alice,
        &leaf_hash_bob,
    };
    uint256_t merkle_root;
    rc = calc_merkle_root(&merkle_root, leaves, ARRAY_SIZE(leaves));
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
    if (strcmp(address, ADDRESS) != 0) {
        printf("address not same\n");
        return;
    }

    wally_free_string(address);

#if 0
    uint8_t tweakPrivKey[EC_PRIVATE_KEY_LEN];
    rc = wally_ec_private_key_bip341_tweak(
        INTERNAL_PUBKEY, sizeof(INTERNAL_PUBKEY),
        merkle_root.data, sizeof(merkle_root),
        0,
        tweakPrivKey, sizeof(tweakPrivKey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_private_key_bip341_tweak fail: %d\n", rc);
        return;
    }
    printf("tweak privkey:   ");
    dump(tweakPrivKey, sizeof(tweakPrivKey));
    if (memcmp(tweakPrivKey, TWEAK_PRIVKEY, sizeof(TWEAK_PRIVKEY)) != 0) {
        printf("tweakPrivKey not same\n");
    }
#endif

    struct wally_tx *tx = NULL;

    // create sighash, sig and wally_tx
    rc = wally_tx_init_alloc(
        2, // version
        0, // locktime
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

    const uint64_t VALUES[] = { PREV_AMOUNT };

    leaf_script = &leaf_script_alice;
    const uint8_t *privkey = ALICE_PRIVKEY;
    uint8_t sig[EC_SIGNATURE_LEN];
    rc = btc_p2tr_sp_sig(
        sig, sizeof(sig),
        0,
        tx,
        scriptPubKeys,
        VALUES, ARRAY_SIZE(VALUES),
        leaf_script->buf.data,  leaf_script->pos,
        WALLY_SIGHASH_DEFAULT,
        privkey
    );
    if (rc != WALLY_OK) {
        printf("error: btc_p2tr_sp_sig fail: %d\n", rc);
        return;
    }

    printf("sig: ");
    dump(sig, sizeof(sig));
    if (memcmp(sig, SIG, sizeof(sig)) != 0) {
        printf("error: sig not same\n");
        return;
    }

    struct wally_tx_witness_stack *wit_stack;
    rc = wally_tx_witness_stack_init_alloc(3, &wit_stack);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_init_alloc fail: %d\n", rc);
        return;
    }

    // [0] sig
    rc = wally_tx_witness_stack_add(wit_stack, sig, sizeof(sig));
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[0] fail: %d\n", rc);
        return;
    }
    // [1] leaf script
    rc = wally_tx_witness_stack_add(wit_stack, leaf_script->buf.data, leaf_script->pos);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[1] fail: %d\n", rc);
        return;
    }
    // [2] control block
    btc_bufp_t ctrl_block;
    btc_bufp_alloc(&ctrl_block, 1 + EC_XONLY_PUBLIC_KEY_LEN + SHA256_LEN);
    btc_bufp_push1(&ctrl_block, 0xc0 + parity);
    btc_bufp_push(&ctrl_block, INTERNAL_PUBKEY, sizeof(INTERNAL_PUBKEY));
    btc_bufp_push(&ctrl_block, leaf_hash_bob.data, sizeof(leaf_hash_bob));
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

    if (txLen != sizeof(TXDATA)) {
        printf("error: length not match: %lu(expect %lu)\n", txLen, sizeof(TXDATA));
    } else if (memcmp(txData, TXDATA, txLen) != 0) {
        printf("error: txData not same\n");
    }

    wally_tx_free(tx);
    btc_bufp_free(&leaf_script_alice);
    btc_bufp_free(&leaf_script_bob);
}
