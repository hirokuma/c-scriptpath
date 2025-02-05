# script path

* Test data: [Toproot - learn me a bitcoin](https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature)
  * [outpoint](https://mempool.space/ja/tx/a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec#vout=0)
  * [spent tx](https://mempool.space/ja/tx/091d2aaadc409298fd8353a4cd94c319481a0b4623fb00872fe240448e93fcbe#vin=0)

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
script: 206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac
tap leaf hash: 858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16
merkle root: 858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16
tweak pubkey: 02f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
parity: 0
witness program: 5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80
address: bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7
sighash: 752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9
sig: 01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01
tx: 020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000
```
