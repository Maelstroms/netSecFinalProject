from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
parameters = dh.generate_parameters(generator=2, key_size=512,
                                     backend=default_backend())

alice_a = parameters.generate_private_key()  ## This is "a" for alice
alice_public_key = alice_a.public_key() ##This is g^a MOD P

bob_b = parameters.generate_private_key() ## This is "b" for Bob
bob_public_key = bob_b.public_key() ## This is g^b MOD p

alice_shared_key = alice_a.exchange(bob_public_key)
bob_shared_key = bob_b.exchange(alice_public_key)



aes_key = alice_shared_key[0:32]




iv = os.urandom(12)
f = open("f1.txt", 'rb')
output = open("f2.txt", 'wb')
decrypted = open("f3.txt",'wb')
plaintext = f.read()

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
encryptor = Cipher(
		 algorithms.AES(aes_key),
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
         algorithms.AES(aes_key),
         modes.GCM(iv, tag),
         backend=default_backend()
).decryptor()

text =  decryptor.update(ciphertext) + decryptor.finalize()
decrypted.write(text)

f.close()
output.close()
decrypted.close()
