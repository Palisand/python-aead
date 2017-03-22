# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AEAD(object):

    def __init__(self, key, backend=default_backend()):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError("key must be 32 bytes long.")

        self.encryption_key = key[16:]
        self.mac_key = key[:16]
        self.backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data, associated_data=b""):
        iv = os.urandom(16)
        return base64.urlsafe_b64encode(
            self._encrypt_from_parts(data, associated_data, iv)
        )

    def _encrypt_from_parts(self, data, associated_data, iv):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()  # + 16

        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        )

        encryptor = cipher.encryptor()
        cipher_text = iv + encryptor.update(padded_data) + encryptor.finalize()  # + 16

        associated_data_length = struct.pack(">Q", len(associated_data) * 8)

        h = hmac.HMAC(self.mac_key, hashes.SHA256(), self.backend)
        h.update(associated_data)
        h.update(cipher_text)
        h.update(associated_data_length)
        mac = h.finalize()

        return cipher_text + mac[:16]  # + 16

    def decrypt(self, data, associated_data=b""):
        decoded_data = base64.urlsafe_b64decode(data)
        mac = decoded_data[-16:]
        iv = decoded_data[0:16]
        cipher_text = decoded_data[16:-16]

        associated_data_length = struct.pack(">Q", len(associated_data) * 8)

        h = hmac.HMAC(self.mac_key, hashes.SHA256(), self.backend)
        h.update(associated_data)
        h.update(iv)
        h.update(cipher_text)
        h.update(associated_data_length)
        if not constant_time.bytes_eq(mac, h.finalize()[:16]):
            raise ValueError("data provided has an invalid signature.")

        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        )

        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(plain_text) + unpadder.finalize()

        return unpadded_data


class FileCrypter(AEAD):  # TODO: test with 500 MB

    CHUNK_SIZE = 1000000  # 10 mb
    LEN_ENCRYPT_DIFF = 48  # PKCS7 padding + iv + hmac

    def __init__(self, key, backend=default_backend(), chunksize=CHUNK_SIZE):
        super().__init__(key, backend)
        self.__chunksize_encrypt = chunksize

    def encrypt_file(self, src, dest):
        self.__crypt(src, dest, self.encrypt)

    def decrypt_file(self, src, dest):
        self.__crypt(src, dest, self.decrypt)

    def __crypt(self, src, dest, method):
        assert src != dest, "The source path must not be identical to the destination path."

        chunksize = self.__chunksize_encrypt if method == self.encrypt else self.__chunksize_decrypt
        with open(src, 'rb') as src_, open(dest, 'wb') as dest_:
            for chunk in iter(lambda: src_.read(chunksize), b''):
                dest_.write(method(chunk))

    @property
    def __chunksize_decrypt(self):
        n = 4 * (self.__chunksize_encrypt + self.LEN_ENCRYPT_DIFF) / 3
        return int(n if n % 4 == 0 else n + 4 - n % 4)