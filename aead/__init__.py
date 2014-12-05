import base64
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AEAD(object):

    def __init__(self, key, backend=default_backend()):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes long.")

        self.encryption_key = key[:16]
        self.mac_key = key[16:]
        self.backend = backend

    @classmethod
    def generate_key():
        pass

    def encrypt(self, data, additional_data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        )

        encryptor = cipher.encryptor()
        cipher_text = iv + encryptor.update(padded_data) + encryptor.finalize()

        additional_data_length = struct.pack(">Q", len(additional_data))

        h = hmac.HMAC(self.mac_key, hashes.SHA256(), self.backend)
        h.update(additional_data)
        h.update(cipher_text)
        h.update(additional_data_length)
        mac = h.finalize()

        return base64.urlsafe_b64encode(cipher_text + mac)

    def decrypt(self, data, additional_data):
        decoded_data = base64.urlsafe_b64decode(data)
        mac = decoded_data[-32:]
        iv = decoded_data[0:16]
        cipher_text = decoded_data[16:-32]

        additional_data_length = struct.pack(">Q", len(additional_data))

        h = hmac.HMAC(self.mac_key, hashes.SHA256(), self.backend)
        h.update(additional_data)
        h.update(iv)
        h.update(cipher_text)
        h.update(additional_data_length)
        h.verify(mac)

        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        )

        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(plain_text) + unpadder.finalize()

        return unpadded_data
