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


class PrivateKey:

    def __init__(self, secret, compressed=True, testnet=False):
        self.secret = secret
        self.compressed = compressed
        self.testnet = testnet
        pk = self.secret.to_bytes(32, 'big')
        sec = _ecc.get_public_key65(pk)
        x = int.from_bytes(sec[1:33], 'big')
        y = int.from_bytes(sec[33:], 'big')
        self.public_key = PublicKey(x, y)

    def hex(self):
        return '{:0>64x}'.format(self.secret)

    def __repr__(self):
        return self.hex()

    def deterministic_k(self, z):
        # RFC6979, optimized for secp256k1
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
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
        k = self.deterministic_k(z)
        r = (G*k).x
        k_inv = pow(k, N-2, N)
        s = (z + r*self.secret) * k_inv % N
        if s > HALF_N: # FIXME
            s = N - s
        return Signature(r, s)

    def wif(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xef'
            else:
                prefix = b'\x80'
        secret_bytes = self.secret.to_bytes(32, 'big')
        # append b'\x01' if compressed
        if self.compressed:
            suffix = b'\x01'
        else:
            suffix = b''
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
        on_curve = pow(y, 2, P) == pow(x, 3, P) + 7
        if not on_curve:
            raise ValueError("(x={}, y={}) not on curve".format(x, y))
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y

    def __repr__(self):
        if self.x is None:
            return 'PublicKey(infinity)'
        else:
            # FIXME: display hex?
            return 'PublicKey({},{})'.format(self.x, self.y)

    def __add__(self, other):
        a = self.sec(compressed=False)
        b = other.sec(compressed=False)
        res = _ecc.point_add(a,b)
        return PublicKey.parse(res)

    def __mul__(self, other):
        if hasattr(other, 'secret'):
            other = other.secret
        res = _ecc.point_multiply(other.to_bytes(32, 'big'), self.sec(compressed=False))
        return PublicKey.parse(res)

    def __truediv__(self, other):
        if hasattr(other, 'secret'):
            other = other.secret
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
        total = G*u + self*v
        return total.x == sig.r

    @classmethod
    def parse(cls, sec_bin):
        if sec_bin[0] != 4:
            sec_bin = _ecc.uncompress_pubkey(sec_bin)
        x = int.from_bytes(sec_bin[1:33], 'big')
        y = int.from_bytes(sec_bin[33:], 'big')
        return cls(x, y)


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        rbin = self.r.to_bytes(32, 'big')
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin  # <1>
        sbin = self.s.to_bytes(32, 'big')
        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = 0x8000000000000000000000000000000000000000000000000000000000000000
P = 2**256 - 2**32 - 977
G = PublicKey(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
