from binascii import hexlify, unhexlify

import hashlib
import math

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def hash160(s):
    return hashlib.ripemd160(hashlib.sha256(s).digest()).digest()

def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    prefix = b'1' * count
    # convert from binary to hex, then hex to integer
    num = int.from_bytes(s, 'big')
    result = b''
    while num > 0:
        num, mod = divmod(num, 58)
        result = bytes([BASE58_ALPHABET[mod]]) + result

    return prefix + bytes(result)


def encode_base58_checksum(s):
    return encode_base58(s + double_sha256(s)[:4]).decode('ascii')


def decode_base58(s, num_bytes=25, strip_leading_zeros=False):
    num = 0
    b = s.encode('ascii')
    print(b)
    for c in s.encode('ascii'):
        num *= 58
        num += int(BASE58_ALPHABET.index(bytes([c])))
    combined = num.to_bytes(num_bytes, 'big')
    if strip_leading_zeros:
        while combined[0] == 0:
            combined = combined[1:]
    checksum = combined[-4:]
    if double_sha256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(
            checksum, double_sha256(combined)[:4]))
    return combined[:-4]


def p2pkh_script(h160):
    '''Takes a hash160 and returns the scriptPubKey'''
    return b'\x76\xa9\x14' + h160 + b'\x88\xac'

def p2sh_script(h160):
    '''Takes a hash160 and returns the scriptPubKey'''
    return b'\xa9\x14' + h160 + b'\x87'

def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i

def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))

def flip_endian(h):
    '''flip_endian takes a hex string and flips the endianness
    Returns a hexadecimal string
    '''
    b = unhexlify(h)
    b_rev = b[::-1]
    return hexlify(b_rev).decode('ascii')

def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')

def h160_to_p2pkh_address(h160, prefix=b'\x00'):
    '''Takes a byte sequence hash160 and returns a p2pkh address string'''
    # p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    return encode_base58_checksum(prefix + h160)

def h160_to_p2sh_address(h160, prefix=b'\x05'):
    '''Takes a byte sequence hash160 and returns a p2sh address string'''
    # p2sh has a prefix of b'\x05' for mainnet, b'\xc0' for testnet
    return encode_base58_checksum(prefix + h160)
