from Crypto.PublicKey import RSA

#Generate priv and pub keys
keypair = RSA.generate(2048)
#Prepare for exporting
keypairstr = keypair.export_key(format='PEM', passphrase='your_key')
pubkey = keypair.publickey()
pubkeystr = pubkey.export_key(format='PEM')