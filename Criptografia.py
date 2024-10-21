import hashlib
import hmac
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

def generate_hmac(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def validate_hmac(key, message, received_hmac):
    generated_hmac = generate_hmac(key, message)
    return hmac.compare_digest(generated_hmac, received_hmac)

def derive_key(password, salt):
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

def validar_fortaleza(password):
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not any(char.isdigit() for char in password):
        return False, "La contraseña debe contener al menos un número."
    if not any(char.isalpha() for char in password):
        return False, "La contraseña debe contener al menos una letra."
    return True, None

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_data, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce.hex(), encrypted_data.hex(), tag.hex()

"""
# Para dividir la cadena en tres partes utilizando el delimitador ":"
nonce, encrypted_bank_acc, tag = data.split(":")
"""
def decrypt_data(nonce, encrypted_data, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
    decrypted_data = cipher.decrypt_and_verify(bytes.fromhex(encrypted_data), bytes.fromhex(tag))
    return decrypted_data.decode()
