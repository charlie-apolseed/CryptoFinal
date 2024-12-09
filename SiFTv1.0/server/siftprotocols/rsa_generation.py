# rsa_generation.py
import os
import sys
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

# Configuration
operation = 'enc'  # default
pubkeyfile = '../client/siftprotocols/pubkey.pem'
privkeyfile = './siftprotocols/privkey.pem'
sign = False

# Utility functions (same as your code)
def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    with open(privkeyfile, "wb") as f:
        f.write(keypair.export_key(format="PEM"))

def load_keypair(privkeyfile):
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

# Key Generation
def generate_keypair():
    keypair = RSA.generate(2048)
    pubkey = keypair.publickey()
    save_publickey(pubkey, pubkeyfile)
    save_keypair(keypair, privkeyfile)


# Encryption
def encrypt(inputText):
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    encryptedData = RSAcipher.encrypt(inputText)
    
    return encryptedData

# Decryption
def decrypt(ciphertext):
    privkey = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(privkey)
    plaintext = RSAcipher.decrypt(ciphertext)
    return plaintext