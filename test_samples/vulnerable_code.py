"""
Sample vulnerable code for testing the scanner
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib

# RSA usage (quantum-vulnerable)
def generate_rsa_key():
    key = RSA.generate(2048)
    return key

def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

# ECC usage (quantum-vulnerable) 
def generate_ecc_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def ecdsa_sign(message, private_key):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

# Weak hash (partially quantum-vulnerable)
def weak_hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

def weak_hash_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

# Strong symmetric crypto (quantum-resistant for now)
def aes_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

# Safe function without crypto
def safe_function():
    return "This function doesn't use cryptography"
