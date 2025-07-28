// HTLC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_script.h>

#include "btc_buf.h"
#include "btc_merkle.h"
#include "btc_p2tr_scriptpath.h"

#include "htlc.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
static const char ADDR_FAMILY[] = "bcrt";

/*
<preimage>
---
OP_SHA256
<paymnet_hash>
OP_EQUAL
OP_IF
    OP_TRUE
OP_ELSE
    OP_FALSE
OP_ENDIF

-------------------
<path#0>
    <Alice_signature>
    <preimage>
    ---
    OP_SHA256
    <paymnet_hash>
    OP_EQUALVERIFY
    <Alice_pubkey>
    OP_CHECKSIG

<path#1>
    <Bob_signature>
    ---
    5
    OP_CHECKSEQUENCEVERIFY
    OP_EQUALVERIFY
    <Bob_pubkey>
    OP_CHECKSIG
*/
static const uint8_t PREIMAGE[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
// 4773d12e2371bb935b9a0f5439b4a1c3ad3f2414b86980f8418d1cfabdfadfef
static const uint8_t PAYMENT_HASH[] = {
    0x47, 0x73, 0xd1, 0x2e, 0x23, 0x71, 0xbb, 0x93,
    0x5b, 0x9a, 0x0f, 0x54, 0x39, 0xb4, 0xa1, 0xc3,
    0xad, 0x3f, 0x24, 0x14, 0xb8, 0x69, 0x80, 0xf8,
    0x41, 0x8d, 0x1c, 0xfa, 0xbd, 0xfa, 0xdf, 0xef,
};

// 00112233445566778899aabbccddee0000112233445566778899aabbccddee00
static const uint8_t ALICE_PRIVKEY[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
};
// 7fa033135f9f099d243ade11f8b9265d58a6316e930ce0cd57824ef967bb629d
static const uint8_t ALICE_PUBKEY[] = {
    0x7f, 0xa0, 0x33, 0x13, 0x5f, 0x9f, 0x09, 0x9d,
    0x24, 0x3a, 0xde, 0x11, 0xf8, 0xb9, 0x26, 0x5d,
    0x58, 0xa6, 0x31, 0x6e, 0x93, 0x0c, 0xe0, 0xcd,
    0x57, 0x82, 0x4e, 0xf9, 0x67, 0xbb, 0x62, 0x9d,
};
// 00112233445566778899aabbccddee0100112233445566778899aabbccddee01
static const uint8_t BOB_PRIVKEY[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01,
};
// 3dce6c620fcabcfedc2ce2c46fbd57ea717db26df30afc95082b2fdd67ecd16a
static const uint8_t BOB_PUBKEY[] = {
    0x3d, 0xce, 0x6c, 0x62, 0x0f, 0xca, 0xbc, 0xfe,
    0xdc, 0x2c, 0xe2, 0xc4, 0x6f, 0xbd, 0x57, 0xea,
    0x71, 0x7d, 0xb2, 0x6d, 0xf3, 0x0a, 0xfc, 0x95,
    0x08, 0x2b, 0x2f, 0xdd, 0x67, 0xec, 0xd1, 0x6a,
};

static const uint8_t INTERNAL_PRIVKEY[] = {
    0x55, 0xd7, 0xc5, 0xa9, 0xce, 0x3d, 0x2b, 0x15,
    0xa6, 0x24, 0x34, 0xd0, 0x12, 0x05, 0xf3, 0xe5,
    0x90, 0x77, 0xd5, 0x13, 0x16, 0xf5, 0xc2, 0x06,
    0x28, 0xb3, 0xa4, 0xb8, 0xb2, 0xa7, 0x6f, 0x4c,
};

// redeem Tapscript address
static const uint32_t CSV_SEQUENCE = 5;
static const int FEE = 300;


static void dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int create_bech32m_address(
    const uint8_t *internal_privkey,
    const char *addr_prefix,
    uint8_t *internal_pubkey,
    uint8_t *tweak_privkey,
    uint8_t *tweak_pubkey,
    char *bech32m_address, size_t bech32m_address_len)
{
    int rc;

    uint8_t ipubkey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_from_private_key(
        internal_privkey, EC_PRIVATE_KEY_LEN,
        ipubkey, sizeof(ipubkey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_from_private_key fail: %d\n", rc);
        return -1;
    }
    if (internal_pubkey) {
        memcpy(internal_pubkey, ipubkey + 1, EC_XONLY_PUBLIC_KEY_LEN);
    }

    uint8_t tpubkey[EC_PUBLIC_KEY_LEN];
    rc = wally_ec_public_key_bip341_tweak(
        ipubkey, sizeof(ipubkey),
        NULL, 0,
        0,
        tpubkey, sizeof(tpubkey));
    if (rc != WALLY_OK) {
        printf("error: wally_ec_public_key_bip341_tweak fail: %d\n", rc);
        return -1;
    }
    if (tweak_pubkey) {
        memcpy(tweak_pubkey, tpubkey + 1, EC_XONLY_PUBLIC_KEY_LEN);
    } else {
        tweak_pubkey = ipubkey + 1;
    }

    uint8_t tprivkey[EC_PRIVATE_KEY_LEN];
    rc = wally_ec_private_key_bip341_tweak(
        internal_privkey, EC_PRIVATE_KEY_LEN,
        NULL, 0,
        0,
        tprivkey, EC_PRIVATE_KEY_LEN);
    if (rc != WALLY_OK) {
        printf("error: wally_ec_private_key_bip341_tweak fail: %d\n", rc);
        return -1;
    }
    if (tweak_privkey) {
        memcpy(tweak_privkey, tprivkey, EC_PRIVATE_KEY_LEN);
    }

    uint8_t wit_prog[WALLY_WITNESSSCRIPT_MAX_LEN];
    size_t wit_prog_len = 0;
    rc = wally_witness_program_from_bytes_and_version(
        tweak_pubkey, EC_XONLY_PUBLIC_KEY_LEN,
        1,
        0,
        wit_prog, sizeof(wit_prog), &wit_prog_len);
    if (rc != WALLY_OK) {
        printf("error: wally_witness_program_from_bytes fail: %d\n", rc);
        return -1;
    }

    char *address;
    rc = wally_addr_segwit_from_bytes(
        wit_prog, wit_prog_len,
        addr_prefix,
        0,
        &address);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_from_bytes fail: %d\n", rc);
        return -1;
    }
    if (bech32m_address) {
        if (strlen(address) + 1 <= bech32m_address_len) {
            strcpy(bech32m_address, address);
        } else {
            printf("error: address too long\n");
            rc = -1;
        }
    }

    wally_free_string(address);

    return rc;
}

// [OP_SHA256 <payment_hash> OP_EQUALVERIFY <Alice_pubkey> OP_CHECKSIG]
static int create_script_preimage(btc_bufp_t *leaf_script_preimage)
{
    btc_bufp_alloc(leaf_script_preimage, 256);
    btc_bufp_push1(leaf_script_preimage, OP_SHA256);
    btc_bufp_push_array(leaf_script_preimage, PAYMENT_HASH, sizeof(PAYMENT_HASH));
    btc_bufp_push1(leaf_script_preimage, OP_EQUALVERIFY);
    btc_bufp_push_array(leaf_script_preimage, ALICE_PUBKEY, sizeof(ALICE_PUBKEY));
    btc_bufp_push1(leaf_script_preimage, OP_CHECKSIG);
    btc_bufp_trunc(leaf_script_preimage);

    return 0;
}

// [OP_5 OP_CHECKSEQUENCEVERIFY OP_DROP <Bob_pubkey> OP_CHECKSIG]
static int create_script_csv(btc_bufp_t *leaf_script_csv)
{
    btc_bufp_alloc(leaf_script_csv, 256);
    btc_bufp_push1(leaf_script_csv, OP_5);
    btc_bufp_push1(leaf_script_csv, OP_CHECKSEQUENCEVERIFY);
    btc_bufp_push1(leaf_script_csv, OP_DROP);
    btc_bufp_push_array(leaf_script_csv, BOB_PUBKEY, sizeof(BOB_PUBKEY));
    btc_bufp_push1(leaf_script_csv, OP_CHECKSIG);
    btc_bufp_trunc(leaf_script_csv);

    return 0;
}

static int leaf_script_hash(btc_bufp_t *leaf_script, uint256_t *leaf_hash)
{
    int rc;
    btc_buf_t leaf_msg = BTC_BUF_INIT();

    btc_buf_alloc(&leaf_msg, 2 + leaf_script->pos);
    leaf_msg.data[0] = 0xc0; // leaf version
    leaf_msg.data[1] = leaf_script->pos; // compact_size(script)
    memcpy(leaf_msg.data + 2, leaf_script->buf.data, leaf_script->pos);

    rc = btc_p2tr_sp_leafhash(leaf_hash->data, leaf_msg.data, leaf_msg.len);
    if (rc != WALLY_OK) {
        printf("error: wally_bip340_tagged_hash: %d\n", rc);
        goto EXIT;
    }

EXIT:
    btc_buf_free(&leaf_msg);
    return rc;
}

void htlc(HTLC_REDEEM_TYPE redeem_type, const char *prevTxStr)
{
    if (redeem_type < HTLC_SCRIPT_ADDRESS || redeem_type > HTLC_CSV_REDEEM) {
        printf("error: invalid redeem type\n");
        return;
    }

    int rc;

    struct wally_tx_input *tx_input0 = NULL;
    struct wally_tx *tx_prev = NULL;
    struct wally_tx *tx_target = NULL;
    btc_bufp_t leaf_script_preimage = BTC_BUFP_INIT();
    btc_bufp_t leaf_script_csv = BTC_BUFP_INIT();
    uint256_t leaf_hash_preimage;
    uint256_t leaf_hash_csv;
    uint8_t ipubkey[EC_XONLY_PUBLIC_KEY_LEN];
    char *address;
    char spend_address[128];

    // leaf script
    rc = create_script_preimage(&leaf_script_preimage);
    if (rc != 0) {
        printf("error: create_script_preimage fail: %d\n", rc);
        goto EXIT;
    }

    rc = create_script_csv(&leaf_script_csv);
    if (rc != 0) {
        printf("error: create_script_csv fail: %d\n", rc);
        goto EXIT;
    }

    // leaf script hash
    rc = leaf_script_hash(&leaf_script_preimage, &leaf_hash_preimage);
    if (rc != WALLY_OK) {
        printf("error: leaf_script_hash(preimage) fail: %d\n", rc);
        goto EXIT;
    }

    rc = leaf_script_hash(&leaf_script_csv, &leaf_hash_csv);
    if (rc != WALLY_OK) {
        printf("error: leaf_script_hash(csv) fail: %d\n", rc);
        goto EXIT;
    }

    // merkle root
    const uint256_t *leaves[2] = {
        &leaf_hash_preimage,
        &leaf_hash_csv,
    };
    uint256_t merkle_root;
    rc = calc_merkle_root(&merkle_root, leaves, ARRAY_SIZE(leaves),
            btc_p2tr_merkle_merge);
    if (rc != 0) {
        printf("error: calc_merkle_root %d\n", rc);
        goto EXIT;
    }

    rc = create_bech32m_address(
        INTERNAL_PRIVKEY,
        ADDR_FAMILY,
        ipubkey,
        NULL,
        NULL,
        spend_address, sizeof(spend_address));
    if (rc != 0) {
        printf("error: create_bech32m_address fail: %d\n", rc);
        goto EXIT;
    }

    // tweak pubkey
    uint8_t tweakXonlyPubKey[EC_XONLY_PUBLIC_KEY_LEN];
    uint8_t witnessProgram[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    int parity;
    rc = btc_p2tr_sp_tweak_pubkey(
        tweakXonlyPubKey,
        witnessProgram,
        &address,
        &parity,
        ipubkey,
        merkle_root.data,
        ADDR_FAMILY
    );

    printf("address: %s\n", address);

    if (redeem_type == HTLC_SCRIPT_ADDRESS) {
        goto EXIT;
    }


    printf("spend_address: %s\n", spend_address);

    // read transaction spent to Tapscript address
    rc = wally_tx_from_hex(
        prevTxStr,
        WALLY_TX_FLAG_USE_WITNESS,
        &tx_prev);
    if (rc != WALLY_OK) {
        printf("error: convert tx data to tx struct fail: %d\n", rc);
        goto EXIT;
    }

    uint8_t tx_prev_txid[WALLY_TXHASH_LEN];
    rc = wally_tx_get_txid(tx_prev, tx_prev_txid, sizeof(tx_prev_txid));
    if (rc != WALLY_OK) {
        printf("error: wally_tx_get_txid fail: %d\n", rc);
        goto EXIT;
    }

    // search previous output index from transaction
    int prevOutIndex;
    for (prevOutIndex = 0; prevOutIndex < tx_prev->num_outputs; prevOutIndex++) {
        if (memcmp(witnessProgram, tx_prev->outputs[prevOutIndex].script, tx_prev->outputs[prevOutIndex].script_len) == 0) {
            printf("witness program match #%d\n", prevOutIndex);
            break;
        }
    }
    if (prevOutIndex >= tx_prev->num_outputs) {
        printf("error: output index mismatch\n");
        goto EXIT;
    }

    rc = wally_tx_init_alloc(
        WALLY_TX_VERSION_2, // version
        0, // locktime
        1, // vin_cnt
        1, // vout_cnt
        &tx_target);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_init_alloc fail: %d\n", rc);
        goto EXIT;
    }

    int sequence;
    if (redeem_type == HTLC_PREIMAGE_REDEEM) {
        sequence = WALLY_TX_SEQUENCE_FINAL;
    } else if (redeem_type == HTLC_CSV_REDEEM) {
        sequence = CSV_SEQUENCE;
    }

    rc = wally_tx_input_init_alloc(
        tx_prev_txid, sizeof(tx_prev_txid),
        prevOutIndex,
        sequence,
        NULL, 0, // no scriptSig
        NULL, // no witness
        &tx_input0);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_input_init_alloc fail: %d\n", rc);
        goto EXIT;
    }
    rc = wally_tx_add_input(tx_target, tx_input0);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_add_input fail: %d\n", rc);
        goto EXIT;
    }
    wally_tx_input_free(tx_input0);

    uint8_t outAddrByte[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
    size_t outAddrLen = 0;
    rc = wally_addr_segwit_to_bytes(
        spend_address,
        ADDR_FAMILY,
        0, outAddrByte, sizeof(outAddrByte), &outAddrLen);
    if (rc != WALLY_OK) {
        printf("error: wally_addr_segwit_to_bytes fail: %d\n", rc);
        return;
    }
    const struct wally_tx_output TX_OUTPUT = {
        .satoshi = tx_prev->outputs[prevOutIndex].satoshi - FEE,
        .script = outAddrByte,
        .script_len = outAddrLen,
        .features = 0,
    };
    rc = wally_tx_add_output(tx_target, &TX_OUTPUT);
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

    const uint64_t VALUES[] = { tx_prev->outputs[prevOutIndex].satoshi };

    btc_bufp_t *target_script;
    uint256_t other_hash;
    const uint8_t *privkey;
    struct wally_tx_witness_stack *wit_stack;
    int stack_num;

    if (redeem_type == HTLC_PREIMAGE_REDEEM) {
        target_script = &leaf_script_preimage;
        other_hash = leaf_hash_csv;
        privkey = ALICE_PRIVKEY;
        stack_num = 4; // sig, preimage, script, control block
    } else if (redeem_type == HTLC_CSV_REDEEM) {
        target_script = &leaf_script_csv;
        other_hash = leaf_hash_preimage;
        privkey = BOB_PRIVKEY;
        stack_num = 3; // sig, script, control block
    }

    uint8_t sig[EC_SIGNATURE_LEN];
    rc = btc_p2tr_sp_sig(
        sig, sizeof(sig),
        0,
        tx_target,
        scriptPubKeys,
        VALUES, ARRAY_SIZE(VALUES),
        target_script->buf.data,  target_script->pos,
        WALLY_SIGHASH_DEFAULT,
        privkey
    );
    if (rc != WALLY_OK) {
        printf("error: btc_p2tr_sp_sig fail: %d\n", rc);
        return;
    }

    rc = wally_tx_witness_stack_init_alloc(stack_num, &wit_stack);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_init_alloc fail: %d\n", rc);
        return;
    }

    // signature
    rc = wally_tx_witness_stack_add(wit_stack, sig, sizeof(sig));
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[sig] fail: %d\n", rc);
        return;
    }
    if (redeem_type == HTLC_PREIMAGE_REDEEM) {
        // preimage
        rc = wally_tx_witness_stack_add(wit_stack, PREIMAGE, sizeof(PREIMAGE));
        if (rc != WALLY_OK) {
            printf("error: wally_tx_witness_stack_add[preimage] fail: %d\n", rc);
            return;
        }
    }
    // script
    rc = wally_tx_witness_stack_add(wit_stack, target_script->buf.data, target_script->pos);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[script] fail: %d\n", rc);
        return;
    }
    // control block
    btc_bufp_t ctrl_block;
    btc_bufp_alloc(&ctrl_block, 1 + EC_XONLY_PUBLIC_KEY_LEN + SHA256_LEN);
    btc_bufp_push1(&ctrl_block, 0xc0 + parity);
    btc_bufp_push(&ctrl_block, ipubkey, sizeof(ipubkey));
    btc_bufp_push(&ctrl_block, other_hash.data, sizeof(other_hash));
    rc = wally_tx_witness_stack_add(wit_stack, ctrl_block.buf.data, ctrl_block.pos);
    btc_bufp_free(&ctrl_block);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_witness_stack_add[control block] fail: %d\n", rc);
        return;
    }
    // set witness to input
    rc = wally_tx_set_input_witness(tx_target, 0, wit_stack);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_set_input_witness fail: %d\n", rc);
        return;
    }
    wally_tx_witness_stack_free(wit_stack);

    uint8_t txData[1024];
    size_t txLen = 0;
    rc = wally_tx_to_bytes(
        tx_target,
        WALLY_TX_FLAG_USE_WITNESS,
        txData, sizeof(txData), &txLen);
    if (rc != WALLY_OK) {
        printf("error: wally_tx_to_bytes fail: %d\n", rc);
        return;
    }
    printf("\nbitcoin-cli sendrawtransaction ");
    dump(txData, txLen);


EXIT:
    wally_free_string(address);
    wally_tx_input_free(tx_input0);
    wally_tx_free(tx_prev);
    wally_tx_free(tx_target);
    btc_bufp_free(&leaf_script_preimage);
    btc_bufp_free(&leaf_script_csv);
}
