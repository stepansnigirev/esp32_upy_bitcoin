from binascii import hexlify, unhexlify

import hashlib
import math

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32_ALPHABET = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]


def hash160(s):
    return hashlib.ripemd160(hashlib.sha256(s).digest()).digest()

def sha256(s):
    return hashlib.sha256(s).digest()

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


def raw_decode_base58(s, num_bytes):
    if type(s) == str:
        b = s.encode('ascii')
    else:
        b = s
    num = 0
    for c in b:
        num *= 58
        # FIXME: why line below work in lepton, not here .. iteration over bytes produces ints in both cases in py and upy ... but this assumes c is a byte ...
        # num += BASE58_ALPHABET.index(c)

        num += BASE58_ALPHABET.index(bytes([c]))
    combined = num.to_bytes(num_bytes, 'big')
    checksum = combined[-4:]
    if double_sha256(combined[:-4])[:4] != checksum:
        raise ValueError('bad checksum {} != {}'.format(
            double_sha256(combined[:-4])[:4].hex(), checksum.hex()))
    return combined[:-4]


def decode_base58(s):
    raw = raw_decode_base58(s, 25)
    return raw[1:]


# next four functions are straight from BIP0173:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
def bech32_polymod(values):
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s):
    return [x >> 5 for x in s] + [0] + [x & 31 for x in s]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def group_32(s):
    '''Convert from 8-bit bytes to 5-bit array of integers'''
    result = []
    unused_bits = 0
    current = 0
    for c in s:
        unused_bits += 8
        current = current * 256 + c
        while unused_bits > 5:
            unused_bits -= 5
            result.append(current >> unused_bits)
            mask = (1 << unused_bits) - 1
            current &= mask
    result.append(current << (5 - unused_bits))
    return result


def encode_bech32(nums):
    '''Convert from 5-bit array of integers to bech32 format'''
    return bytes([BECH32_ALPHABET[n] for n in nums])


def encode_bech32_checksum(s, testnet=False):
    '''Convert a witness program to a bech32 address'''
    if testnet:
        prefix = b'tb'
    else:
        prefix = b'bc'
    version = s[0]
    if version > 0:
        version -= 0x50
    length = s[1]
    data = [version] + group_32(s[2:2 + length])
    checksum = bech32_create_checksum(prefix, data)
    bech32 = encode_bech32(data + checksum)
    result = prefix + b'1' + bech32
    return result.decode('ascii')


def decode_bech32(s):
    '''Convert a bech32 address to a witness program'''
    hrp, raw_data = s.encode('ascii').split(b'1')
    data = [BECH32_ALPHABET.index(c) for c in raw_data]
    if not bech32_verify_checksum(hrp, data):
        raise ValueError('bad address: {}'.format(s))
    version = data[0]
    number = 0
    for digit in data[1:-6]:
        number = (number << 5) + digit
    num_bytes = (len(data) - 7) * 5 // 8
    bits_to_ignore = (len(data) - 7) * 5 % 8
    number >>= bits_to_ignore
    witness = number.to_bytes(num_bytes, 'big')
    if version == 0:
        version_byte = b'\x00'
    else:
        version_byte = encode_varint(version + 0x50)
    if num_bytes < 2 or num_bytes > 40:
        raise ValueError('bytes out of range: {}'.format(num_bytes))
    length_byte = encode_varint(num_bytes)
    return version_byte + length_byte + bytes(witness)


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

def encode_varstr(b):
    return encode_varint(len(b)) + b

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

def reverse_bytes(b):
    return bytes(reversed(b))
