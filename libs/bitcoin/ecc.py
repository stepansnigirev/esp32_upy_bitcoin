from binascii import hexlify
from io import BytesIO

import hmac
import hashlib

from .helper import (
    decode_base58,
    encode_base58_checksum,
    encode_bech32_checksum,
    hash160,
    p2pkh_script
)

import _ecc


class PrivateKey:

    def __init__(self, secret, testnet=True):
        self.secret = secret
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
        if s*2 > N:
            s = N - s
        return Signature(r, s)

    def address(self, compressed=True):
        return self.public_key.address(compressed=compressed, testnet=self.testnet)

    def wif(self, compressed=True, testnet=False):
        # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        # prepend b'\xef' on testnet, b'\x80' on mainnet
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        # append b'\x01' if compressed
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)



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
        if isinstance(other, int):
            other = G * other
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

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def p2pkh_script(self, compressed=True):
        h160 = self.hash160(compressed)
        return p2pkh_script(h160)

    def address(self, compressed=True, testnet=True):
        '''Returns the address string'''
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)

    def bech32_address(self, testnet=False):
        '''Returns the address string'''
        from bitcoin.script import p2wpkh_script
        h160 = self.hash160()
        raw = p2wpkh_script(h160).raw_serialize()
        return encode_bech32_checksum(raw, testnet)

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
P = 2**256 - 2**32 - 977
G = PublicKey(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
