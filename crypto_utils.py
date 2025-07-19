# crypto_utils.py

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Generate DH parameters
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_keys():
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    real_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(real_ciphertext) + decryptor.finalize()).decode()
