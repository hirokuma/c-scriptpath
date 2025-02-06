#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "libwally-core/include/wally_address.h"
#include "libwally-core/include/wally_core.h"
#include "libwally-core/include/wally_crypto.h"
#include "libwally-core/include/wally_map.h"
#include "libwally-core/include/wally_script.h"
#include "libwally-core/include/wally_transaction.h"


int sample3(void) {
    int rc;

    // Wallyの初期化
    rc = wally_init(0);
    assert(rc == WALLY_OK);

    // 支払元アウトプットの情報
    uint8_t sender_txhash[SHA256_LEN] = { /* 支払元トランザクションのハッシュ */ };
    uint32_t sender_tx_output_index = 0; // 支払元トランザクションのアウトプットインデックス
    uint64_t sender_satoshi = 10000;   // 支払元アウトプットの金額(satoshi)
    uint8_t sender_private_key[EC_PRIVATE_KEY_LEN] = { /* 支払元アドレスの秘密鍵 */ };
    char *sender_address = "bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 支払元アドレス (p2wpkh)


    // 送信先アドレスの情報
    char *receiver_address = "bc1qyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"; // 送信先アドレス (p2wpkh)
    uint64_t receiver_satoshi = 9000; // 送信金額(satoshi)


    // トランザクションの作成
    struct wally_tx *tx = NULL;
    rc = wally_tx_init_alloc(2, 0, 1, 1, &tx); // version, locktime, input_count, output_count
    assert(rc == WALLY_OK);


    // inputの作成
    struct wally_tx_input tx_input = {0};
    memcpy(tx_input.txhash, sender_txhash, SHA256_LEN);
    tx_input.index = sender_tx_output_index;
    tx_input.sequence = 0xFFFFFFFF; // Replace with your desired sequence number
    rc = wally_tx_add_input(tx, &tx_input);
    assert(rc == WALLY_OK);


    // outputの作成
    uint8_t receiver_scriptpubkey[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    size_t receiver_scriptpubkey_len = 0;
    rc = wally_addr_segwit_to_bytes(receiver_address, "bc", 0, receiver_scriptpubkey, sizeof(receiver_scriptpubkey), &receiver_scriptpubkey_len);
    assert(rc == WALLY_OK);

    struct wally_tx_output tx_output = {0};
    tx_output.satoshi = receiver_satoshi;
    tx_output.script = receiver_scriptpubkey;
    tx_output.script_len = receiver_scriptpubkey_len;
    rc = wally_tx_add_output(tx, &tx_output);
    assert(rc == WALLY_OK);


    // 署名
    uint8_t sender_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    rc = wally_ec_public_key_from_private_key(sender_private_key, EC_PRIVATE_KEY_LEN, sender_pubkey, sizeof(sender_pubkey));
    assert(rc == WALLY_OK);

    uint8_t sender_scriptpubkey[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    size_t sender_scriptpubkey_len = 0;
    rc = wally_addr_segwit_to_bytes(sender_address, "bc", 0, sender_scriptpubkey, sizeof(sender_scriptpubkey), &sender_scriptpubkey_len);
    assert(rc == WALLY_OK);

    uint32_t flags = WALLY_SIGHASH_ALL;
    uint8_t signature[EC_SIGNATURE_LEN + 1];

    // sighashの計算
    uint8_t sighash[SHA256_LEN];
    struct wally_map *prev_scripts = NULL;
    rc = wally_map_init_alloc(1, NULL, &prev_scripts);
    assert(rc == WALLY_OK);
    rc = wally_map_add_integer(prev_scripts, 0, sender_scriptpubkey, sender_scriptpubkey_len);
    assert(rc == WALLY_OK);
    uint64_t values[] = {sender_satoshi};

    rc = wally_tx_get_btc_signature_hash(tx, 0, prev_scripts, values, 1, sender_scriptpubkey, sender_scriptpubkey_len, 0, WALLY_NO_CODESEPARATOR, NULL, 0, flags, sighash, sizeof(sighash));
    assert(rc == WALLY_OK);


    // wally_ec_sig_from_bytesを使った署名
    rc = wally_ec_sig_from_bytes(sender_private_key, EC_PRIVATE_KEY_LEN, sighash, sizeof(sighash), EC_FLAG_ECDSA, signature, sizeof(signature) - 1);
    assert(rc == WALLY_OK);
    signature[EC_SIGNATURE_LEN] = flags; // sighash type を追加


    struct wally_tx_witness_stack *witness = NULL;
    rc = wally_tx_witness_stack_init_alloc(2, &witness);
    assert(rc == WALLY_OK);

    rc = wally_tx_witness_stack_add(witness, signature, sizeof(signature));
    assert(rc == WALLY_OK);
    rc = wally_tx_witness_stack_add(witness, sender_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN-1);
    assert(rc == WALLY_OK);
    rc = wally_tx_set_input_witness(tx, 0, witness);
    assert(rc == WALLY_OK);

    // シリアライズ
    uint8_t tx_bytes[1024];
    size_t tx_bytes_written = 0;
    rc = wally_tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS, tx_bytes, sizeof(tx_bytes), &tx_bytes_written);
    assert(rc == WALLY_OK);


    // 後処理
    wally_map_free(prev_scripts);
    wally_tx_free(tx);
    wally_cleanup(0);

    // tx_bytesにBitcoinトランザクションのバイト列が格納される
    // これをBitcoinネットワークにブロードキャストする

    return 0;
}
