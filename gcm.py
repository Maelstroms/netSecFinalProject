import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

from cryptography.hazmat.primitives import hashes

def encrypt():
    # Generate a random 96-bit IV.

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(b"awesome")
    
    key =  digest.finalize()
    
    iv = os.urandom(12)
    f = open("f1.txt", 'rb')
    output = open("f2.txt", 'wb')
    decrypted = open("f3.txt",'wb')
    plaintext = f.read()

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

    

    output.write(ciphertext)

    tag = encryptor.tag

    
    decryptor = Cipher(
         algorithms.AES(key),
         modes.GCM(iv, tag),
         backend=default_backend()
    ).decryptor()

    text =  decryptor.update(ciphertext) + decryptor.finalize()
    decrypted.write(text)

    f.close()
    output.close()
    decrypted.close()



def Main():
    encrypt()
        
    
  

        
if __name__ == "__main__":
    Main()