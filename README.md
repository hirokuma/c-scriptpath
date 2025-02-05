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
mkdir -p libs/libwally-core

git clone https://github.com/ElementsProject/libwally-core.git
cd libwally-core
git checkout -b v1.3.1 release_1.3.1

./tools/autogen.sh
./configure --prefix `pwd`/../libs/libwally-core --enable-minimal --disable-elements --enable-standard-secp --with-system-secp256k1 --disable-shared
make
make install
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
```
