## Python application that can be used to encrypt and sign a file to be sent by email.
##The sender knows the public key of the destination, and has a private key to sign the file.
##The application can also be used by the receiver to decrypt the file using his private key
##and to verify the signature using the public key of the sender.

import os
import argparse
import sys, types,pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as padd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

## A class Message having components Key, Msg and Sign
class Message :
    def __init__(self,key, msg, sign, iv):
        self.key = key
        self.msg = msg
        self.sign = sign
        self.iv = iv


## rsa_Signature is the function to sign the message with private key of the sender
## Given : Message and a file containing the key of the sender
## Returns : Signature
        

def rsa_signature(message, private_file_name) :
    with open(private_file_name, "rb") as key_file:
             private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
    signer = private_key.signer(
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
             ),
            hashes.SHA256()
         )
    
    signer.update(message)
    signature = signer.finalize()
    return signature

##rsa_Encryption to encrypt AES symmetric key using public key of destination
## Given : Message and a file containing the key of destination
## Returns : Ciphertext
    

def rsa_encryption(message, public_file_name) :
    f = open (public_file_name,'rb')
    public_pem_data = f.read()
    public_key = load_pem_public_key(public_pem_data, backend=default_backend())
    ciphertext = public_key.encrypt(
         message,
             padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA1()),
                 algorithm=hashes.SHA1(),
                 label=None
             )
    )
    f.close()
    return ciphertext


##rsa_decryption to decrypt ciphertext at Destination end with destination private key
## Given : Ciphertext and destination private key
## Returns : Plaintext

    
def rsa_decryption(ciphertext, private_file_name) :
    with open(private_file_name, "rb") as key_file:
         private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
    plaintext = private_key.decrypt(
     ciphertext,
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
         )
     )
    return plaintext


##main_decryption_function() is called when -d option appears in command line argument
## This function decrypts the encrypted file sent to the destination.

def main_decryption_function () : 
    parser = argparse.ArgumentParser(description='encryption and decryption protocol')
    parser.add_argument('-e', dest='encrypt', action='store_true',help='encrypt message')
    parser.add_argument('-d', dest='decrypt', action='store_true',help='decrypt message')
    parser.add_argument('destination_key_filename')
    parser.add_argument('sender_key_filename')
    parser.add_argument('ciphertext_file')
    parser.add_argument('output_plaintext_file')
    args = parser.parse_args()
    file_obj = open (args.ciphertext_file, 'rb')
    m1 = pickle.load(file_obj)
    key = rsa_decryption (m1.key, args.destination_key_filename)
    iv = m1.iv
    backend = default_backend()
    message = m1.msg
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypt_str = decryptor.update(message) + decryptor.finalize()
    unpadder = padd.PKCS7(128).unpadder()
    data = unpadder.update(decrypt_str)
    data += unpadder.finalize()
    ptfile = open(args.output_plaintext_file, 'wb')
    ptfile.write(data)
    ptfile.close()
    
    
##main_encryption_function is called when -e option appears in command line argument
## Thsi function encrypts the message and key

def main_encryption_function() :
    parser = argparse.ArgumentParser(description='encryption and decryption protocol')
    parser.add_argument('-e', dest='encrypt', action='store_true',help='encrypt message')
    parser.add_argument('-d', dest='decrypt', action='store_true',help='decrypt message')
    parser.add_argument('destination_key_filename')
    parser.add_argument('sender_key_filename')
    parser.add_argument('input_file')
    parser.add_argument('output_file')
    args = parser.parse_args()

    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    ## Block size is 16*8 bits
    f = open(args.input_file, 'rb')
#    f1 = open('f2.txt', 'wb')
#    fd = open('f3.txt', 'wb')
    output = open(args.output_file, 'wb')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    data = f.read()
    print "Data", data
    padding = padd.PKCS7(128).padder()
    padded_data = padding.update(bytes(data))
    print "Padded Object", padded_data
    padded_data += padding.finalize()
    print "A Padded Object", padded_data
    ct = encryptor.update(padded_data) + encryptor.finalize()
#    f1.write(ct)
    enc_sign = rsa_signature(ct, args.sender_key_filename)
    enc_key = rsa_encryption(key, args.destination_key_filename)
    m = Message (enc_key, ct, enc_sign, iv)
    pickle.dump (m, output)
    output.close()
    f.close()


## This is the main function of the program, using AES symmetric cryptography along with RSA
## to send data from sender to destination


def Main():
    argm = sys.argv

    if len(argm) != 6:
        raise Exception("Invalid Arguments - Please input 5 arguments in form -e/d key_file key_file input_filename output_file")
        
    if argm[1] == '-e' : 
        main_encryption_function()
    if argm[1] == '-d' :
        main_decryption_function()
##    else : 
##        print "Please give valid input"
        
    
  

        
if __name__ == "__main__":
    Main()
