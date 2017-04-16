import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from cryptography.hazmat.primitives import hashes


def decryptor(key,iv,tag,ciphertext)
    
    decryptor = Cipher(
         algorithms.AES(key),
         modes.GCM(iv, tag),
         backend=default_backend()
    ).decryptor()

    plaintext =  decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext,key,iv


def Main():
    encrypt()
        
    
  

        
if __name__ == "__main__":
    Main()