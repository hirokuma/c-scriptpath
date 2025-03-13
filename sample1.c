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

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
//      internal pubkey:    924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329
//      leaf script:        206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac
//                              20 <leaf pubkey=6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0>
//                              OP_CHECKSIG
//      leaf privkey:       9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189
//      merkle root:        858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16
//      tweak:              479785dd89a6441dbe00c7661865a0cc68672e8021f4547ac7f89ac26ac049f2
//      tweak pubkey:       f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
//      witness prog:       5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
//      sighash:            752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9
//      signature:          01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01

static const uint8_t INTERNAL_PUBKEY[] = {
    0x92, 0x4c, 0x16, 0x3b, 0x38, 0x5a, 0xf7, 0x09,
    0x34, 0x40, 0x18, 0x4a, 0xf6, 0xfd, 0x62, 0x44,
    0x93, 0x6d, 0x12, 0x88, 0xcb, 0xb4, 0x1c, 0xc3,
    0x81, 0x22, 0x86, 0xd3, 0xf8, 0x3a, 0x33, 0x29,
};

static const uint8_t LEAF_HASH[] = {
    0x85, 0x8d, 0xfe, 0x26, 0xa3, 0xdd, 0x48, 0xa2,
    0xc1, 0xfc, 0xee, 0x1d, 0x63, 0x1f, 0x0a, 0xad,
    0xf6, 0xa6, 0x11, 0x35, 0xfc, 0x51, 0xf7, 0x57,
    0x58, 0xe9, 0x45, 0xbc, 0xa5, 0x34, 0xef, 0x16,
};
static const uint8_t MERKLE_ROOT[] = {
    0x85, 0x8d, 0xfe, 0x26, 0xa3, 0xdd, 0x48, 0xa2,
    0xc1, 0xfc, 0xee, 0x1d, 0x63, 0x1f, 0x0a, 0xad,
    0xf6, 0xa6, 0x11, 0x35, 0xfc, 0x51, 0xf7, 0x57,
    0x58, 0xe9, 0x45, 0xbc, 0xa5, 0x34, 0xef, 0x16,
};

static const uint8_t TWEAK_PUBKEY[] = {
    0xf3, 0x77, 0x8d, 0xef, 0xe5, 0x17, 0x3a, 0x9b,
    0xf7, 0x16, 0x95, 0x75, 0x11, 0x62, 0x24, 0xf9,
    0x61, 0xc0, 0x3c, 0x72, 0x5c, 0x0e, 0x98, 0xb8,
    0xda, 0x8f, 0x15, 0xdf, 0x29, 0x19, 0x4b, 0x80,
};

static const uint8_t WITNESS_PROGRAM[] = {
    0x51, 0x20, 0xf3, 0x77, 0x8d, 0xef, 0xe5, 0x17,
    0x3a, 0x9b, 0xf7, 0x16, 0x95, 0x75, 0x11, 0x62,
    0x24, 0xf9, 0x61, 0xc0, 0x3c, 0x72, 0x5c, 0x0e,
    0x98, 0xb8, 0xda, 0x8f, 0x15, 0xdf, 0x29, 0x19,
    0x4b, 0x80,
};

static const char ADDRESS[] = "bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7";
static const uint64_t PREV_AMOUNT = 20000UL;

// d1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c:0
#define OUTPOINT_TXHASH { \
    0x3c, 0xfe, 0x8b, 0x95, 0xd2, 0x25, 0x02, 0x69,\
    0x8f, 0xd9, 0x88, 0x37, 0xf8, 0x3d, 0x8d, 0x4b,\
    0xe3, 0x1e, 0xe3, 0xed, 0xdd, 0x9d, 0x1a, 0xb1,\
    0xa9, 0x56, 0x54, 0xc6, 0x46, 0x04, 0xc4, 0xd1,\
}
static const uint32_t OUTPOINT_INDEX = 0;
static const uint32_t SEQUENCE = 0xffffffff;
static const char OUTADDR[] = "bc1qphn5thzcmrnzum68hh3se4vqf2pqzmu7hl34z0";
static const uint64_t OUT_AMOUNT = 15000UL;

static const uint8_t LEAF_PRIVKEY[] = {
    0x9b, 0x8d, 0xe5, 0xd7, 0xf2, 0x0a, 0x8e, 0xbb,
    0x02, 0x6a, 0x82, 0xba, 0xba, 0xc3, 0xaa, 0x47,
    0xa0, 0x08, 0xde, 0xbb, 0xfd, 0xe5, 0x34, 0x89,
    0x62, 0xb2, 0xc4, 0x65, 0x20, 0xbd, 0x51, 0x89,
};
static const uint8_t LEAF_PUBKEY[] = {
    0x6d, 0x4d, 0xdc, 0x0e, 0x47, 0xd2, 0xe8, 0xf8,
    0x2c, 0xbe, 0x2f, 0xc2, 0xd0, 0xd7, 0x49, 0xe7,
    0xbd, 0x33, 0x38, 0x11, 0x2c, 0xec, 0xdc, 0x76,
    0xd8, 0xf8, 0x31, 0xae, 0x66, 0x20, 0xdb, 0xe0,
};
static const uint8_t SIG[] = {
    0x01, 0x76, 0x91, 0x05, 0xcb, 0xcb, 0xdc, 0xaa,
    0xee, 0x5e, 0x58, 0xcd, 0x20, 0x1b, 0xa3, 0x15,
    0x24, 0x77, 0xfd, 0xa3, 0x14, 0x10, 0xdf, 0x8b,
    0x91, 0xb4, 0xae, 0xe2, 0xc4, 0x86, 0x4c, 0x77,
    0x00, 0x61, 0x5e, 0xfb, 0x42, 0x5e, 0x00, 0x2f,
    0x14, 0x6a, 0x39, 0xca, 0x0a, 0x4f, 0x29, 0x24,
    0x56, 0x67, 0x62, 0xd9, 0x21, 0x3b, 0xd3, 0x3f,
    0x82, 0x5f, 0xad, 0x83, 0x97, 0x7f, 0xba, 0x7f,
    0x01,
};

// https://mempool.space/ja/tx/797505b104b5fb840931c115ea35d445eb1f64c9279bf23aa5bb4c3d779da0c2#vin=0
static const uint8_t TXDATA[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x3c,
    0xfe, 0x8b, 0x95, 0xd2, 0x25, 0x02, 0x69, 0x8f,
    0xd9, 0x88, 0x37, 0xf8, 0x3d, 0x8d, 0x4b, 0xe3,
    0x1e, 0xe3, 0xed, 0xdd, 0x9d, 0x1a, 0xb1, 0xa9,
    0x56, 0x54, 0xc6, 0x46, 0x04, 0xc4, 0xd1, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x01, 0x98, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x16, 0x00, 0x14, 0x0d, 0xe7, 0x45, 0xdc,
    0x58, 0xd8, 0xe6, 0x2e, 0x6f, 0x47, 0xbd, 0xe3,
    0x0c, 0xd5, 0x80, 0x4a, 0x82, 0x01, 0x6f, 0x9e,
    0x03, 0x41, 0x01, 0x76, 0x91, 0x05, 0xcb, 0xcb,
    0xdc, 0xaa, 0xee, 0x5e, 0x58, 0xcd, 0x20, 0x1b,
    0xa3, 0x15, 0x24, 0x77, 0xfd, 0xa3, 0x14, 0x10,
    0xdf, 0x8b, 0x91, 0xb4, 0xae, 0xe2, 0xc4, 0x86,
    0x4c, 0x77, 0x00, 0x61, 0x5e, 0xfb, 0x42, 0x5e,
    0x00, 0x2f, 0x14, 0x6a, 0x39, 0xca, 0x0a, 0x4f,
    0x29, 0x24, 0x56, 0x67, 0x62, 0xd9, 0x21, 0x3b,
    0xd3, 0x3f, 0x82, 0x5f, 0xad, 0x83, 0x97, 0x7f,
    0xba, 0x7f, 0x01, 0x22, 0x20, 0x6d, 0x4d, 0xdc,
    0x0e, 0x47, 0xd2, 0xe8, 0xf8, 0x2c, 0xbe, 0x2f,
    0xc2, 0xd0, 0xd7, 0x49, 0xe7, 0xbd, 0x33, 0x38,
    0x11, 0x2c, 0xec, 0xdc, 0x76, 0xd8, 0xf8, 0x31,
    0xae, 0x66, 0x20, 0xdb, 0xe0, 0xac, 0x21, 0xc0,
    0x92, 0x4c, 0x16, 0x3b, 0x38, 0x5a, 0xf7, 0x09,
    0x34, 0x40, 0x18, 0x4a, 0xf6, 0xfd, 0x62, 0x44,
    0x93, 0x6d, 0x12, 0x88, 0xcb, 0xb4, 0x1c, 0xc3,
    0x81, 0x22, 0x86, 0xd3, 0xf8, 0x3a, 0x33, 0x29,
    0x00, 0x00, 0x00, 0x00,
};


static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void sample1(void)
{
    int rc;

    // leaf script
    //      20 <leaf pubkey=6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0>
    //      OP_CHECKSIG
    btc_bufp_t leaf_script;
    btc_bufp_alloc(&leaf_script, 50);
    btc_bufp_push1(&leaf_script, sizeof(LEAF_PUBKEY));
    btc_bufp_push(&leaf_script, LEAF_PUBKEY, sizeof(LEAF_PUBKEY));
    btc_bufp_push1(&leaf_script, OP_CHECKSIG);
    btc_bufp_trunc(&leaf_script);
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
    if (memcmp(leaf_hash.data, LEAF_HASH, sizeof(leaf_hash)) != 0) {
        printf("leaf_hash not same\n");
        return;
    }

    btc_buf_free(&leaf_msg);

    // merkle root
    const uint256_t *leaves[1] = {
        &leaf_hash,
    };
    uint256_t merkle_root;
    rc = calc_merkle_root(&merkle_root, leaves, ARRAY_SIZE(leaves),
                btc_p2tr_merkle_merge);
    if (rc != 0) {
        printf("error: calc_merkle_root %d\n", rc);
        return;
    }
    printf("merkle root: ");
    dump(merkle_root.data, sizeof(merkle_root));
    if (memcmp(merkle_root.data, MERKLE_ROOT, sizeof(merkle_root)) != 0) {
        printf("merkle_root not same\n");
        return;
    }

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
        "bc"
    );
    printf("tweak pubkey: ");
    dump(tweakXonlyPubKey, sizeof(tweakXonlyPubKey));
    printf("parity: %d\n", parity);
    if (memcmp(tweakXonlyPubKey, TWEAK_PUBKEY, sizeof(TWEAK_PUBKEY)) != 0) {
        printf("tweakXonlyPubKey not same\n");
        return;
    }
    printf("witness program: ");
    dump(witnessProgram, sizeof(witnessProgram));
    if (memcmp(witnessProgram, WITNESS_PROGRAM, sizeof(WITNESS_PROGRAM)) != 0) {
        printf("witnessProgram not same\n");
        return;
    }
    printf("address: %s\n", address);
    if (strcmp(address, ADDRESS) != 0) {
        printf("address not same\n");
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
        "bc",
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
        WITNESS_PROGRAM, sizeof(WITNESS_PROGRAM));
    if (rc != WALLY_OK) {
        printf("error: wally_map_add_integer fail: %d\n", rc);
        return;
    }

    const uint64_t VALUES[] = { PREV_AMOUNT };

    uint8_t sig[EC_SIGNATURE_LEN + 1];
    rc = btc_p2tr_sp_sig(
        sig, sizeof(sig),
        0,
        tx,
        scriptPubKeys,
        VALUES, ARRAY_SIZE(VALUES),
        leaf_script.buf.data,  leaf_script.pos,
        WALLY_SIGHASH_ALL,
        LEAF_PRIVKEY
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

    if (txLen != sizeof(TXDATA)) {
        printf("error: length not match: %lu(expect %lu)\n", txLen, sizeof(TXDATA));
    } else if (memcmp(txData, TXDATA, txLen) != 0) {
        printf("error: txData not same\n");
    }

    wally_tx_free(tx);
}
