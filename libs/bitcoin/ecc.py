from binascii import hexlify
from io import BytesIO

import hmac
import hashlib

from .helper import (
    decode_base58,
    encode_base58_checksum,
    hash160,
    p2pkh_script
)

import _ecc

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class FieldElement:
    def __init__(self, num, prime):
        self.num = num
        self.prime = prime
        if self.num >= self.prime or self.num < 0:
            error = 'Num {} not in field range 0 to {}'.format(
                self.num, self.prime-1)
            raise RuntimeError(error)

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        if other is None:
            return True
        return self.num != other.num or self.prime != other.prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __add__(self, other):
        if not hasattr(other, 'prime'):
            other = self.__class__(other, self.prime)
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        num = (self.num + other.num) % self.prime
        prime = self.prime
        return self.__class__(num, prime)

    def __sub__(self, other):
        if not hasattr(other, 'prime'):
            other = self.__class__(other, self.prime)
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        num = (self.num - other.num) % self.prime
        prime = self.prime
        return self.__class__(num, prime)

    def __mul__(self, other):
        if hasattr(other, 'sec'): # if it is a PublicKey
            return other.__mul__(self)
        if not hasattr(other, 'prime'):
            other = self.__class__(other, self.prime)
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, n):
        prime = self.prime
        num = pow(self.num, n % (prime-1), prime)
        return self.__class__(num, prime)

    def __truediv__(self, other):
        if not hasattr(other, 'prime'):
            other = self.__class__(other, self.prime)
        if self.prime != other.prime:
            raise RuntimeError('Primes must be the same')
        other_inv = pow(other.num, self.prime - 2, self.prime)
        num = (self.num * other_inv) % self.prime
        prime = self.prime
        return self.__class__(num, prime)

class PrivateKey(FieldElement):
    def __init__(self, num, compressed=False, testnet=False):
        super().__init__(num=num, prime=N)
        self.compressed = compressed
        self.testnet = testnet
        pk = self.num.to_bytes(32, 'big')
        sec = _ecc.get_public_key65(pk)
        x = int.from_bytes(sec[1:33], 'big')
        y = int.from_bytes(sec[33:], 'big')
        self.public_key = PublicKey(x, y)

    def hex(self):
        return '{:0>64x}'.format(self.num)

    def __repr__(self):
        return self.hex()

    def deterministic_k(self, z):
        # RFC6979, optimized for secp256k1
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.num.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while 1:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def sign(self, z):
        # use deterministic signatures
        k = self.deterministic_k(z)
        # r is the x coordinate of the resulting point k*G
        r = (k*G).x.num
        # remember 1/k = pow(k, N-2, N)
        k_inv = pow(k, N-2, N)
        # s = (z+r*secret) / k
        s = (z + r*self.num) * k_inv % N
        if s > N/2:
            s = N - s
        # return an instance of Signature:
        # Signature(r, s)
        return Signature(r, s)

    def wif(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xef'
            else:
                prefix = b'\x80'
        # convert the secret from integer to a 32-bytes in big endian using
        # num.to_bytes(32, 'big')
        secret_bytes = self.num.to_bytes(32, 'big')
        # append b'\x01' if compressed
        if self.compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)

    def address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\x6f'
            else:
                prefix = b'\x00'
        return self.public_key.address(compressed=self.compressed, prefix=prefix)

    def segwit_redeem_script(self):
        return self.public_key.segwit_redeem_script()

    def segwit_address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xc4'
            else:
                prefix = b'\x05'
        return self.public_key.segwit_address(prefix=prefix)

    @classmethod
    def parse(cls, wif):
        secret_bytes = decode_base58(
            wif,
            num_bytes=40,
            strip_leading_zeros=True,
        )
        # remove the first and last if we have 34, only the first if we have 33
        testnet = secret_bytes[0] == 0xef
        if len(secret_bytes) == 34:
            secret_bytes = secret_bytes[1:-1]
            compressed = True
        elif len(secret_bytes) == 33:
            secret_bytes = secret_bytes[1:]
            compressed = False
        else:
            raise RuntimeError('not valid WIF')
        secret = int.from_bytes(secret_bytes, 'big')
        return cls(secret, compressed=compressed, testnet=testnet)

class PublicKey:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y \
            or self.a != other.a or self.b != other.b

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})'.format(self.x, self.y)

    def __add__(self, other):
        a = self.sec(compressed=False)
        b = other.sec(compressed=False)
        res = _ecc.point_add(a,b)
        return PublicKey.parse(res)

    def __mul__(self, other):
        if hasattr(other, 'num'):
            other = other.num
        res = _ecc.point_multiply(other.to_bytes(32, 'big'), self.sec(compressed=False))
        return PublicKey.parse(res)

    def __truediv__(self, other):
        if hasattr(other, 'prime'):
            other = other.num
        return self.__mul__(pow(other, N-2, N))

    def sec(self, compressed=True):
        if compressed:
            if self.y % 2 == 0:
                return b'\x02' + self.x.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.to_bytes(32, 'big') \
                + self.y.to_bytes(32, 'big')    

    def h160(self, compressed=True):
        return hash160(self.sec(compressed))

    def p2pkh_script(self, compressed=True):
        h160 = self.h160(compressed)
        return p2pkh_script(h160)

    def address(self, compressed=True, prefix=b'\x00'):
        '''Returns the address string'''
        h160 = self.h160(compressed)
        return encode_base58_checksum(prefix + h160)

    def segwit_redeem_script(self):
        return b'\x16\x00\x14' + self.h160(True)

    def segwit_address(self, prefix=b'\x05'):
        address_bytes = hash160(self.segwit_redeem_script()[1:])
        return encode_base58_checksum(prefix + address_bytes)

    def verify(self, z, sig):
        # remember sig.r and sig.s are the main things we're checking
        # remember 1/s = pow(s, N-2, N)
        s_inv = pow(sig.s, N-2, N)
        # u = z / s
        u = z * s_inv % N
        # v = r / s
        v = sig.r * s_inv % N
        # u*G + v*P should have as the x coordinate, r
        total = u*G + v*self
        return total.x.num == sig.r

    @classmethod
    def parse(cls, sec_bin):
        if sec_bin[0] != 4:
            sec_bin = _ecc.uncompress_pubkey(sec_bin)
        x = int.from_bytes(sec_bin[1:33], 'big')
        y = int.from_bytes(sec_bin[33:], 'big')
        return cls(x, y)

G = PublicKey(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
