# rsa_generation.py
import sys, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

# Configuration
operation = 'enc'  # default
pubkeyfile = '/client/pubkey.pem'
privkeyfile = '/server/keypair.pem'
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
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, "wb") as f:
        f.write(keypair.export_key(format="PEM", passphrase=passphrase))

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

def newline(s):
    return s + b'\n'

# Key Generation
def generate_keypair():
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    pubkey = keypair.publickey()
    save_publickey(pubkey, pubkeyfile)
    save_keypair(keypair, privkeyfile)
    print('Done.')

# Encryption
def encrypt(inputText):
    print('Encrypting...')
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

  

    padded_plaintext = Padding.pad(inputText, AES.block_size, style="pkcs7")
    symkey = Random.get_random_bytes(32)
    AEScipher = AES.new(symkey, AES.MODE_CBC)
    iv = AEScipher.iv
    ciphertext = AEScipher.encrypt(padded_plaintext)
    encsymkey = RSAcipher.encrypt(symkey)

    # Prepare components to be returned
    encrypted_data = 'encrypted_aes_key'+ newline(b64encode(encsymkey)) 
    +'iv' + newline(b64encode(iv)) 
    +'ciphertext' + newline(b64encode(ciphertext))
    
     
    print('RSA encryption complete.')
    return encrypted_data

# Decryption
def decrypt(inputfile, outputfile):
    print('Decrypting...')
    encsymkey, iv, ciphertext, signature = b'', b'', b'', None

    with open(inputfile, 'rb') as f:
        sep = f.readline()
        while sep:
            data = f.readline().strip()
            sep = sep.strip()
            if sep == b'--- ENCRYPTED AES KEY ---':
                encsymkey = b64decode(data)
            elif sep == b'--- IV FOR CBC MODE ---':
                iv = b64decode(data)
            elif sep == b'--- CIPHERTEXT ---':
                ciphertext = b64decode(data)
            elif sep == b'--- SIGNATURE ---':
                signature = b64decode(data)
                sign = True
            sep = f.readline()

    if not (encsymkey and iv and ciphertext):
        print('Error: Could not parse content of input file.')
        sys.exit(1)

    if sign:
        pubkey = load_publickey(pubkeyfile)
        verifier = PKCS1_PSS.new(pubkey)
        hashfn = SHA256.new()
        hashfn.update(encsymkey + iv + ciphertext)
        if not verifier.verify(hashfn, signature):
            print('Signature verification failed.')
            return

    privkey = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(privkey)
    symkey = RSAcipher.decrypt(encsymkey)
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv=iv)
    padded_plaintext = AEScipher.decrypt(ciphertext)
    plaintext = Padding.unpad(padded_plaintext, AES.block_size, "pkcs7")

    with open(outputfile, 'wb') as f:
        f.write(plaintext)
    print('Done.')