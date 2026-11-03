#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Encode and decode BASE58, P2PKH and P2SH addresses."""

from .script import hash256, hash160, sha256, CScript, OP_0
from .util import hex_str_to_bytes

ADDRESS_BCRT1_UNSPENDABLE = 'n1BurnXXXXXXXXXXXXXXXXXXXXXXU1qejP'
chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def byte_to_base58(b, version):
    result = ''
    hex_str = b.hex()
    hex_str = chr(version).encode('latin-1').hex() + hex_str
    checksum = hash256(hex_str_to_bytes(hex_str)).hex()
    hex_str += checksum[:8]
    value = int('0x' + hex_str, 0)
    while value > 0:
        result = chars[value % 58] + result
        value //= 58
    while hex_str[:2] == '00':
        result = chars[0] + result
        hex_str = hex_str[2:]
    return result


# TODO: def base58_decode

def keyhash_to_p2pkh(hash_input, main=False):
    assert (len(hash_input) == 20)
    # Neurai base58 versions: mainnet 'N' (53); testnet and regtest 't' (127).
    version = 53 if main else 127
    return byte_to_base58(hash_input, version)


def scripthash_to_p2sh(hash_in, main=False):
    assert (len(hash_in) == 20)
    version = 117 if main else 196
    return byte_to_base58(hash_in, version)


def key_to_p2pkh(key, main=False):
    key = check_key(key)
    return keyhash_to_p2pkh(hash160(key), main)


def script_to_p2sh(script, main=False):
    script = check_script(script)
    return scripthash_to_p2sh(hash160(script), main)


def key_to_p2sh_p2wpkh(key, main=False):
    key = check_key(key)
    p2shscript = CScript([OP_0, hash160(key)])
    return script_to_p2sh(p2shscript, main)


def script_to_p2sh_p2wsh(script, main=False):
    script = check_script(script)
    p2shscript = CScript([OP_0, sha256(script)])
    return script_to_p2sh(p2shscript, main)


def check_key(key):
    if type(key) is str:
        key = hex_str_to_bytes(key)  # Assuming this is hex string
    if type(key) is bytes and (len(key) == 33 or len(key) == 65):
        return key
    assert False


def check_script(script):
    if type(script) is str:
        script = hex_str_to_bytes(script)  # Assuming this is hex string
    if type(script) is bytes or type(script) is CScript:
        return script
    assert False


BECH32M_CONST = 0x2bc830a3
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32m_address(hrp, witver, program):
    """Witness v1+ address. Regtest: 'tnc' (AuthScript v1), 'tpq' (v2), 'tnq' (v3)."""
    data = [witver] + convertbits(program, 8, 5)
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data
    polymod = bech32_polymod(values + [0] * 6) ^ BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)
