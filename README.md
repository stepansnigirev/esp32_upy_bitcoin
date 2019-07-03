# esp32_upy_bitcoin

## Installation

Download submodules:

```bash
git submodule update --init --recursive
```

Cross-compile micropython

```bash
cd micropython/mpy-cross
make
cd ../..
```

Also added 2 lines in `micropython/ports/esp32/mpconfigport.h`:

```cpp
#define MODULE_HASHLIB_ENABLED      (1)
#define MODULE_ECC_ENABLED          (1)
```

Copy over the micropython files:

```bash
cp -r libs/* micropython/ports/esp32/modules/
```

Compile firmware:

```bash
ESPIDF=~/esp/esp-idf make USER_C_MODULES=../../../usermods
```

Upload firmware

```bash
esptool.py --chip esp32 --port <port> --baud 460800 erase_flash
esptool.py --chip esp32 --port <port> --baud 460800 write_flash -z 0x1000 build/firmware.bin
```

Then we have two new modules:
- `bitcoin.ecc` containing ecc primitives
- `hashlib` with all hash functions

```
$ screen /dev/ttyUSB0 115200
>>> import bitcoin
>>> dir(bitcoin)
['__class__', '__name__', '__path__', 'helper', 'PrivateKey', 'PublicKey', 'ecc']
>>> dir(bitcoin.ecc)
['__class__', '__name__', 'BytesIO', '_ecc', 'hashlib', 'hexlify', 'hash160', 'encode_base58_checksum', 'decode_base58', 'p2pkh_script', 'hmac', 'N', 'FieldElement', 'PrivateKey', 'PublicKey', 'G']
>>> import hashlib
>>> dir(hashlib)
['__class__', '__name__', 'ripemd160', 'sha1', 'sha256', 'sha512']
```

## Reference

- [Useful doc for user modules](https://micropython.org/resources/docs/en/latest/develop/cmodules.html)
