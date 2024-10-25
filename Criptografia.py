import hashlib
import hmac
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from flask_mail import Message  # Importa Message para enviar correos
import random
import base64


# Deriva una clave de 32 bytes a partir de una contraseña y una salt
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

def encrypt_data(plain_data, key):
    # Creamos un objeto cipher utilizando la clase AES en modo GCM (el nonce se genera automáticamente)
    cipher = AES.new(key, AES.MODE_GCM)

    # Convertimos el texto plano en bytes con plain_data.encode()
    # Ciframos y generamos un tag de autenticidad con cipher.encrypt_and_digest()
    ciphertext, tag = cipher.encrypt_and_digest(plain_data.encode())

    # Codificamos nonce, ciphertext y tag en base64 (separados por ':')
    encrypted_message = f"{base64.b64encode(cipher.nonce).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}"

    return encrypted_message


def decrypt_data(encrypted_message, key):
    # Separar nonce, ciphertext y tag del mensaje cifrado
    nonce, encrypted_data, tag = encrypted_message.split(':')
    nonce = base64.b64decode(nonce)
    encrypted_data = base64.b64decode(encrypted_data)
    tag = base64.b64decode(tag)
    # Crear un objeto de cifrado AES en modo GCM utilizando la clave y el nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Descifrar el texto cifrado y verificar la autenticidad utilizando el tag
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    return decrypted_data.decode()

# Mover las funciones aquí
def generate_token():
    """Genera un token de 6 dígitos"""
    return str(random.randint(100000, 999999))

def send_token_via_email(user_email, token, mail):
    """Envía el token al correo del usuario"""
    msg = Message('Código de verificación', recipients=[user_email])
    msg.body = f'Tu código de verificación es: {token}'
    mail.send(msg)

