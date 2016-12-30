'''Export secret GPG key using BIP13 derivation scheme.

IMPORTANT: Never run this code with your own mnemonic on a PC
with an internet connection or with any kind of persistent storage.
It may leak your mnemonic, exposing any secret key managed by the
TREZOR - which may result in Bitcoin loss!!!
'''
from __future__ import print_function

import ctypes as c
import getpass
import hashlib
import struct

import ecdsa

import trezor_agent.device.interface as interface
import trezor_agent.gpg.client as client
import trezor_agent.gpg.encode as encode
import trezor_agent.gpg.protocol as protocol
import trezor_agent.util as util

curve_name = 'nist256p1'
passphrase = ''

timestamp = 1
user_id = 'testing'
lib = c.cdll.LoadLibrary('./libtrezor-crypto.so')


class HDNode(c.Structure):
    _fields_ = [
        ('depth', c.c_uint32),
        ('child_num', c.c_uint32),
        ('chain_code', c.c_uint8 * 32),
        ('private_key', c.c_uint8 * 32),
        ('public_key', c.c_uint8 * 33),
    ]


def sigencode(r, s, _):
    return (r, s)


def create_signer(signing_key):
    def signer(digest):
        return signing_key.sign_digest_deterministic(
            digest, hashfunc=hashlib.sha256, sigencode=sigencode)
    return signer


def derive(mnemonic, addr):
    node = HDNode()

    seed = (c.c_uint8 * 64)()
    lib.mnemonic_to_seed(mnemonic, passphrase, seed, 0)
    lib.hdnode_from_seed(seed, 64, curve_name, c.byref(node))
    for i in addr:
        res = lib.hdnode_private_ckd(c.byref(node), c.c_uint32(i))
        assert res == 1, (res, i)
    lib.hdnode_fill_public_key(c.byref(node))
    secexp = util.bytes2num(node.private_key)

    curve = ecdsa.NIST256p
    sk = ecdsa.SigningKey.from_secret_exponent(
        secexp=secexp,
        curve=curve,
        hashfunc=hashlib.sha256)

    assert (bytearray(sk.verifying_key.to_string())[:32] ==
            bytearray(node.public_key)[1:33])
    return sk


def pack(sk):
    secexp = util.bytes2num(sk.to_string())
    mpi_bytes = protocol.mpi(secexp)
    checksum = sum(bytearray(mpi_bytes)) & 0xFFFF
    return b'\x00' + mpi_bytes + struct.pack('>H', checksum)


def export_key(mnemonic, ident, private=False):
    d = client.Client(user_id, curve_name)
    pk = d.pubkey(ecdh=False)

    sk = derive(mnemonic, ident.get_bip32_address(ecdh=False))
    assert sk.verifying_key.to_string() == pk.to_string()
    signer_func = create_signer(sk)
    primary = protocol.PublicKey(
        curve_name=curve_name, created=timestamp,
        verifying_key=sk.verifying_key, ecdh=False)

    result = encode.create_primary(user_id=user_id,
                                   pubkey=primary,
                                   signer_func=signer_func,
                                   secret_bytes=(pack(sk) if private else b''))

    pk = d.pubkey(ecdh=True)
    sk = derive(mnemonic, ident.get_bip32_address(ecdh=True))
    assert sk.verifying_key.to_string() == pk.to_string()
    subkey = protocol.PublicKey(
        curve_name=curve_name, created=timestamp,
        verifying_key=sk.verifying_key, ecdh=True)
    result = encode.create_subkey(primary_bytes=result,
                                  subkey=subkey,
                                  signer_func=signer_func,
                                  secret_bytes=(pack(sk) if private else b''))
    return result



def main():
    print(__doc__)
    mnemonic = getpass.getpass('Enter your mnemonic: ')
    ident = interface.Identity('gpg://' + user_id, curve_name)

    print('Use "gpg2 --import" on the following GPG key blocks:\n')
    print(protocol.armor(export_key(mnemonic, ident, private=False), 'PUBLIC KEY BLOCK'))
    print(protocol.armor(export_key(mnemonic, ident, private=True), 'PRIVATE KEY BLOCK'))


if __name__ == '__main__':
    main()