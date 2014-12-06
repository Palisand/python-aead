import base64
import binascii

import pytest

from aead import AEAD


def test_vector():
    key = base64.urlsafe_b64encode(binascii.unhexlify(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ))

    data = binascii.unhexlify(
        "41206369706865722073797374656d206d757374206e6f742062652072657175"
        "6972656420746f206265207365637265742c20616e64206974206d7573742062"
        "652061626c6520746f2066616c6c20696e746f207468652068616e6473206f66"
        "2074686520656e656d7920776974686f757420696e636f6e76656e69656e6365"
    )

    iv = binascii.unhexlify("1af38c2dc2b96ffdd86694092341bc04")

    additional_data = binascii.unhexlify(
        "546865207365636f6e64207072696e6369706c65206f66204175677573746520"
        "4b6572636b686f666673"
    )

    cryptor = AEAD(key)
    foo = cryptor._encrypt_from_parts(data, additional_data, iv)

    assert binascii.hexlify(foo) == (
        b"1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279"
        b"a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2"
        b"fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c8"
        b"6e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59f"
        b"bd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db"
        b"652c3fa36b0a7c5b3219fab3a30bc1c4"
    )


def test_key_length():
    key = base64.urlsafe_b64encode(b"foobar")

    with pytest.raises(ValueError):
        AEAD(key)


def test_round_trip_encrypt_decrypt():
    aead = AEAD(AEAD.generate_key())
    ct = aead.encrypt(b"Hello, World!", b"Goodbye, World!")
    assert aead.decrypt(ct, b"Goodbye, World!") == b"Hello, World!"


def test_invalid_signature():
    aead = AEAD(AEAD.generate_key())
    ct = aead.encrypt(b"Hello, World", b"Goodbye, World!")
    with pytest.raises(ValueError):
        aead.decrypt(ct, b"foobar")
