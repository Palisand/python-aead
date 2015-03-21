from hypothesis import given

from aead import AEAD


@given(bytes, bytes)
def test_round_trip_encrypt_decrypt(plaintext, associated_data):
    cryptor = AEAD(AEAD.generate_key())
    ct = cryptor.encrypt(plaintext, associated_data)
    assert plaintext == cryptor.decrypt(ct, associated_data)
