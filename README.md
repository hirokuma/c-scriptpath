# script path

* Test data
  * sample1: [Toproot - learn me a bitcoin](https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature)
    * [outpoint](https://mempool.space/ja/tx/a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec#vout=0)
    * [spent tx](https://mempool.space/ja/tx/091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe#vin=0)
  * sample2: [js-scriptpath](https://github.com/hirokuma/js-scriptpath/blob/a4222d84fcdbeec01e5e069f04db4a5e0ca48c2f/README.md#run)
    * regtest real data

## prepare

I use system installed `libsecp256k1`(built with `--enable-module-recovery`).  
(Maybe "libsecp256k1-zkp" works fine too).

```bash
git clone https://github.com/ElementsProject/libwally-core.git
cd libwally-core
git checkout -b v1.4.0 release_1.4.0

./tools/autogen.sh
./configure --enable-minimal --disable-elements --enable-standard-secp --with-system-secp256k1 --disable-shared
make
sudo make install
```

## build

```bash
git clone https://github.com/hirokuma/c-scriptpath.git
cd c-scriptpath
make
```

## run

```console
$ ./tst
- sample1 ----------------
script: 206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac
tap leaf hash: 858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16
merkle root: 858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16
tweak pubkey: f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
parity: 0
witness program: 5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
address: bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7
sig: 01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01
tx: 020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000


- sample2 ----------------
internal pubkey: 96cb997b084bdb0ab8697ea3680451409312613bcac477dec392696b99ed5bad
Alice script: 207fa033135f9f099d243ade11f8b9265d58a6316e930ce0cd57824ef967bb629dac
Bob script: 203dce6c620fcabcfedc2ce2c46fbd57ea717db26df30afc95082b2fdd67ecd16aac
Alice leaf hash: e08bb40b3057b5161b190760f21e33c4914d62e2cc831943a10a41bca7e7f9b1
Bob leaf hash: 47b07ec5a831973b30f67f0dd2449e8e1455a32a967564a56f71518f0a31bf28
merkle root: 2a41cfb18d00116b00284f380621970d622fc17e1f2c71a6460e5025e6a72694
tweak pubkey: e73d06c3fe2521e5b711fd18653736a5f609ff945dbe52aff582686f1e69e3a3
parity: 1
witness program: 5120e73d06c3fe2521e5b711fd18653736a5f609ff945dbe52aff582686f1e69e3a3
address: bcrt1puu7sdsl7y5s7tdc3l5vx2dek5hmqnlu5tkl99tl4sf5x78nfuw3stzh7vk
sig: a2e2a27bff7727101474ddb8674652fb00c31722b81e9ba9f0b21d19cb58c370909ffbf642acb27538d0967a191f779dd44dd7f7a512082c49f1eea1393e2efe
tx: 02000000000101bdaf6be98727a8034ca59f21113053d17d89468946d2b9ff860712effcbcf8ee0100000000ffffffff01b882010000000000160014450589517d5d42e7da15d9dc9b1264ede92956380340a2e2a27bff7727101474ddb8674652fb00c31722b81e9ba9f0b21d19cb58c370909ffbf642acb27538d0967a191f779dd44dd7f7a512082c49f1eea1393e2efe22207fa033135f9f099d243ade11f8b9265d58a6316e930ce0cd57824ef967bb629dac41c196cb997b084bdb0ab8697ea3680451409312613bcac477dec392696b99ed5bad47b07ec5a831973b30f67f0dd2449e8e1455a32a967564a56f71518f0a31bf2800000000


- sample3 ----------------
script: 029b00b187
tap leaf hash: aaa8ba566b6254cd5275676cbb75c9df56c784f2aa1a41496c6e0398cee89785
merkle root: aaa8ba566b6254cd5275676cbb75c9df56c784f2aa1a41496c6e0398cee89785
tweak pubkey: 0c5cddf9ca09101885ce76ffc4ce0650681690477571e95aead92fb5394bb75b
parity: 0
witness program: 51200c5cddf9ca09101885ce76ffc4ce0650681690477571e95aead92fb5394bb75b
address: bcrt1pp3wdm7w2pygp3pwwwmlufnsx2p5pdyz8w4c7jkh2myhm2w2tkads4st9hf
tx: 020000000001014e01b6c2354f7d4a6df8bdb8457f087bd42eaac7c4e103e8ee25a14818254c980000000000fdffffff01983a000000000000160014d116846349274371586729117c74bf2a47d5310e03029b0005029b00b18721c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33299b000000


- sample4 ----------------
script: 55b287
tap leaf hash: 1124701590da23bbe45cc88cd2dbbcf29eff73c596dc041b44b4b8edd8e00f58
merkle root: 1124701590da23bbe45cc88cd2dbbcf29eff73c596dc041b44b4b8edd8e00f58
tweak pubkey: 3272e3229fc21b6f23834d14515a4c441d9c38772eda25d3da83ce3a8b29ed3e
parity: 0
witness program: 51203272e3229fc21b6f23834d14515a4c441d9c38772eda25d3da83ce3a8b29ed3e
address: bcrt1pxfewxg5lcgdk7gurf529zkjvgswecwrh9mdzt576s08r4zefa5lqe4wa7e
tx: 020000000001017b17189af816263db1d2ea5b6ad4d6ce6808e49ad96c5d639f66c7d222d8a17201000000000500000001983a000000000000160014d116846349274371586729117c74bf2a47d5310e0301050355b28721c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000


- sample5 ----------------
internal pubkey: f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c
Alice script: 029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac
Bob script: a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac
Alice leaf hash: c81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c9
Bob leaf hash: 632c8632b4f29c6291416e23135cf78ecb82e525788ea5ed6483e3c6ce943b42
merkle root: 41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b
tweak pubkey: a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
parity: 1
witness program: 5120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951
address: bc1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gspmmz4d
address not same
```

## HTLC sample

Regtest HTLC sample

* script 1

```text
    <Alice_signature>
    <preimage>
    ---
    OP_SHA256
    <paymnet_hash>
    OP_EQUALVERIFY
    <Alice_pubkey>
    OP_CHECKSIG
```

* script 2

```text
    <Bob_signature>
    ---
    5
    OP_CHECKSEQUENCEVERIFY
    OP_EQUALVERIFY
    <Bob_pubkey>
    OP_CHECKSIG
```

### Run

```console
$ cd htlc
$ make
$ ./tst
```

1. Enter `1` and show an HTLC script address.
2. Send BTC to the script address on Regtest and get a TXID.
3. Get the raw transaction.
4. Enter `2` and input the raw transaction, show a raw transaction to redeem by preimage.
5. Enter `3` and input the raw transaction, show a raw transaction to redeem by Delay(>= 5 blocks).

