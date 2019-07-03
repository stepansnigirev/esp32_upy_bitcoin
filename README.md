# esp32_upy_bitcoin

To compile:

```bash
ESPIDF=~/esp/esp-idf make USER_C_MODULES=../../../usermods
```

Also added 2 lines in `micropython/ports/esp32/mpconfigport.h`:

```cpp
#define MODULE_HASHLIB_ENABLED      (1)
#define MODULE_ECC_ENABLED          (1)
```

and then we got two modules: `_ecc` and `hashlib` with all hash functions