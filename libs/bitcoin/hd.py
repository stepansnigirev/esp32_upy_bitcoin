import hmac

from hashlib import sha512
from hmac import HMAC
from io import BytesIO
from pbkdf2 import PBKDF2
from binascii import unhexlify

from bitcoin.ecc import PublicKey, PrivateKey, N
from bitcoin.helper import (
    encode_base58_checksum,
    hash160,
    int_to_little_endian,
    raw_decode_base58,
    sha256,
)
from bitcoin.mnemonic import secure_mnemonic, WORD_LIST
from bitcoin.script import p2wpkh_script


PBKDF2_ROUNDS = 2048
MAINNET_XPRV = unhexlify('0488ade4')
MAINNET_YPRV = unhexlify('049d7878')
MAINNET_ZPRV = unhexlify('04b2430c')
TESTNET_XPRV = unhexlify('04358394')
TESTNET_YPRV = unhexlify('044a4e28')
TESTNET_ZPRV = unhexlify('045f18bc')
MAINNET_XPUB = unhexlify('0488b21e')
MAINNET_YPUB = unhexlify('049d7cb2')
MAINNET_ZPUB = unhexlify('04b24746')
TESTNET_XPUB = unhexlify('043587cf')
TESTNET_YPUB = unhexlify('044a5262')
TESTNET_ZPUB = unhexlify('045f1cf6')


class HDPrivateKey:

    def __init__(self, private_key, chain_code, depth, fingerprint,
                 child_number, testnet=False):
        self.private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
        self.testnet = testnet
        self.pub = HDPublicKey(
            public_key=private_key.public_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=testnet,
        )

    def xprv(self):
        if self.testnet:
            version = TESTNET_XPRV
        else:
            version = MAINNET_XPRV
        depth = int_to_little_endian(self.depth, 1)
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        prv = b'\x00' + self.private_key.secret.to_bytes(32, 'big')
        return encode_base58_checksum(
            version + depth + fingerprint + child_number + chain_code + prv)

    def zprv(self):
        if self.testnet:
            version = TESTNET_ZPRV
        else:
            version = MAINNET_ZPRV
        depth = int_to_little_endian(self.depth, 1)
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        prv = b'\x00' + self.private_key.secret.to_bytes(32, 'big')
        return encode_base58_checksum(
            version + depth + fingerprint + child_number + chain_code + prv)

    def xpub(self):
        return self.pub.xpub()

    def zpub(self):
        return self.pub.zpub()

    @classmethod
    def from_seed(cls, seed, path, testnet=False):
        raw = HMAC(key=b'Bitcoin seed', msg=seed, digestmod=sha512).digest()
        private_key = PrivateKey(secret=int.from_bytes(raw[:32], 'big'))
        chain_code = raw[32:]
        root = cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=0,
            fingerprint=b'\x00\x00\x00\x00',
            child_number=0,
            testnet=testnet,
        )
        return root.traverse(path)

    @classmethod
    def generate(cls, password=b'', entropy=0, testnet=False):
        mnemonic = secure_mnemonic(entropy=entropy)
        return mnemonic, cls.from_mnemonic(mnemonic, password=password, testnet=testnet)

    @classmethod
    def from_mnemonic(cls, mnemonic, password=b'', path=b'm', testnet=False):
        binary_seed = bytearray()
        words = mnemonic.split()
        if len(words) not in (12, 15, 18, 21, 24):
            raise ValueError('you need 12, 15, 18, 21, or 24 words')
        number = 0
        for word in words:
            index = WORD_LIST.index(word)
            number = (number << 11) + index
        # checksum is the last n bits where n = (# of words / 3)
        checksum_bits_length = len(words) // 3
        checksum = number & ((1 << checksum_bits_length) - 1)
        bits_to_ignore = (8 - checksum_bits_length) % 8
        data_num = number >> checksum_bits_length
        data = data_num.to_bytes(checksum_bits_length * 4, 'big')
        computed_checksum = sha256(data)[0] >> bits_to_ignore
        if checksum != computed_checksum:
            raise ValueError('words fail checksum: {}'.format(words))
        # what does this do?
        # normalized_words = []
        # for word in words:
            # normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
        # normalized_mnemonic = ' '.join(normalized_words)
        normalized_mnemonic = ' '.join(words)
        seed = PBKDF2(
            normalized_mnemonic,
            b'mnemonic' + password,
            iterations=PBKDF2_ROUNDS,
            macmodule=hmac,
            digestmodule=sha512,
        ).read(64)
        return cls.from_seed(seed, path, testnet=testnet)

    def traverse(self, path):
        current = self
        components = path.split(b'/')[1:]
        for child in components:
            if child.endswith(b"'"):
                hardened = True
                index = int(child[:-1].decode('ascii'))
            else:
                hardened = False
                index = int(child.decode('ascii'))
            current = current.child(index, hardened)
        return current

    @classmethod
    def parse(cls, s):
        raw = raw_decode_base58(s.read(111), num_bytes=82)
        version = raw[:4]
        if version in (TESTNET_XPRV, TESTNET_YPRV, TESTNET_ZPRV):
            testnet = True
        elif version in (MAINNET_XPRV, MAINNET_YPRV, MAINNET_ZPRV):
            testnet = False
        else:
            raise ValueError('not an xprv, yprv or zprv: {}'.format(version))
        depth = raw[4]
        fingerprint = raw[5:9]
        child_number = int.from_bytes(raw[9:13], 'big')
        chain_code = raw[13:45]
        private_key = PrivateKey(secret=int.from_bytes(raw[46:], 'big'))
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=testnet,
        )

    def serialize(self):
        return self.zprv().encode('ascii')

    def child(self, index, hardened=False):
        if index >= 0x80000000:
            raise ValueError('child number should always be less than 2^31')
        sec = self.private_key.public_key.sec()
        fingerprint = hash160(sec)[:4]
        if hardened:
            index += 0x80000000
            pk = self.private_key.secret.to_bytes(32, 'big')
            data = b'\x00' + pk + index.to_bytes(4, 'big')
            raw = HMAC(
                key=self.chain_code, msg=data, digestmod=sha512).digest()
        else:
            data = sec + index.to_bytes(4, 'big')
            raw = HMAC(
                key=self.chain_code, msg=data, digestmod=sha512).digest()
        secret = (int.from_bytes(raw[:32], 'big') +
                  self.private_key.secret) % N
        private_key = PrivateKey(secret=secret)
        chain_code = raw[32:]
        depth = self.depth + 1
        child_number = index
        return HDPrivateKey(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=self.testnet,
        )

    def wif(self):
        return self.private_key.wif(testnet=self.testnet)

    def address(self):
        return self.pub.address()

    def bech32_address(self):
        return self.pub.bech32_address()


class HDPublicKey:

    def __init__(self, public_key, chain_code, depth, fingerprint,
                 child_number, testnet=False):
        self.public_key = public_key
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
        self.testnet = testnet

    def xpub(self):
        if self.testnet:
            version = TESTNET_XPUB
        else:
            version = MAINNET_XPUB
        depth = int_to_little_endian(self.depth, 1)
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        sec = self.public_key.sec()
        return encode_base58_checksum(
            version + depth + fingerprint + child_number +
            chain_code + sec)

    def zpub(self):
        if self.testnet:
            version = TESTNET_ZPUB
        else:
            version = MAINNET_ZPUB
        depth = int_to_little_endian(self.depth, 1)
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        sec = self.public_key.sec()
        return encode_base58_checksum(
            version + depth + fingerprint + child_number +
            chain_code + sec)

    def traverse(self, path):
        current = self
        for child in path.split(b'/')[1:]:
            current = current.child(int(child))
        return current

    @classmethod
    def parse(cls, s):
        raw = raw_decode_base58(s.read(111), num_bytes=82)
        version = raw[:4]
        if version in (TESTNET_XPUB, TESTNET_YPUB, TESTNET_ZPUB):
            testnet = True
        elif version in (MAINNET_XPUB, MAINNET_YPUB, MAINNET_ZPUB):
            testnet = False
        else:
            raise ValueError('not an xpub, ypub or zpub: {}'.format(version))
        depth = raw[4]
        fingerprint = raw[5:9]
        child_number = int.from_bytes(raw[9:13], 'big')
        chain_code = raw[13:45]
        public_key = PublicKey.parse(raw[45:])
        return cls(
            public_key=public_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=testnet,
        )

    def serialize(self):
        return self.zpub().encode('ascii')

    def child(self, index):
        if index >= 0x80000000:
            raise ValueError('child number should always be less than 2^31')
        sec = self.public_key.sec()
        data = sec + index.to_bytes(4, 'big')
        raw = HMAC(key=self.chain_code, msg=data, digestmod=sha512).digest()
        public_key = self.public_key + int.from_bytes(raw[:32], 'big')
        chain_code = raw[32:]
        depth = self.depth + 1
        fingerprint = hash160(sec)[:4]
        child_number = index
        return HDPublicKey(
            public_key=public_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=self.testnet,
        )

    def p2wpkh_script_pubkey(self):
        return p2wpkh_script(self.hash160())

    def hash160(self):
        return self.public_key.hash160()

    def address(self):
        return self.public_key.address(testnet=self.testnet)

    def bech32_address(self):
        return self.public_key.bech32_address(testnet=self.testnet)
