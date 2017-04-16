import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from cryptography.hazmat.primitives import hashes

def encrypt(plaintext,key,iv):
    # Generate a random 96-bit IV.

    
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return ciphertext, iv, tag, key

    

    def decrypt(ciphertext, key,iv,tag)
    
    decryptor = Cipher(
         algorithms.AES(key),
         modes.GCM(iv, tag),
         backend=default_backend()
    ).decryptor()

    plaintext =  decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


