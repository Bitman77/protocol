import Crypto.Random
from Crypto.Random import random, get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Signature import pkcs1_15

# generate 256 bit key for encrypting and decrypting the cryptocurrency data
aes_key = get_random_bytes(32)

# generate 2048 bit RSA keys for authentication, key exchange and digital signatures
def generate_rsa_keys():
    private_key = RSA.generate(2048, Crypto.Random.get_random_bytes)
    public_key = private_key.publickey()
    return private_key, public_key

# generate PKCS#1 v1.5 padded RSA signature using private key
def sign_data(private_key, data):
    hashed_data = SHA256.new(data)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hashed_data)
    return signature

# verify PKCS#1 v1.5 padded RSA signature using public key and original data
def verify_data(public_key, signature, data):
    hashed_data = SHA256.new(data)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hashed_data, signature)
        return True
    except:
        return False
