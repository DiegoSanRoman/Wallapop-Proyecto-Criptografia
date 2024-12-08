from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from flask_mail import Message
import random
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Deriva una clave de 32 bytes a partir de una contraseña y una salt
def derive_key(password, salt):
    """
    Derives a 32-byte key from a password and a salt using the scrypt key derivation function.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use in the key derivation.
    Returns:
        bytes: The derived key.
    """
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)


def encrypt_data(plain_data, key):
    """
    Encrypts plain text data using AES encryption in GCM mode.

    Args:
        plain_data (str): The plain text data to encrypt.
        key (bytes): The encryption key.

    Returns:
        str: The encrypted message in the format 'nonce:ciphertext:tag' encoded in base64.
    """
    # Creamos un objeto cipher utilizando el algoritmo AES en modo GCM (el nonce se genera automáticamente)
    cipher = AES.new(key, AES.MODE_GCM)

    # Convertimos el texto plano en bytes con plain_data.encode()
    # Ciframos y generamos un tag de autenticidad con cipher.encrypt_and_digest()
    ciphertext, tag = cipher.encrypt_and_digest(plain_data.encode())

    # Codificamos nonce, ciphertext y tag en base64 (separados por ':')
    encrypted_message = f"{base64.b64encode(cipher.nonce).decode()}:{base64.b64encode(ciphertext).decode()}:{base64.b64encode(tag).decode()}"

    return encrypted_message


def decrypt_data(encrypted_message, key):
    """
    Decrypts an encrypted message using AES encryption in GCM mode.

    Args:
        encrypted_message (str): The encrypted message in the format 'nonce:ciphertext:tag' encoded in base64.
        key (bytes): The decryption key.

    Returns:
        str: The decrypted plain text data.

    Raises:
        ValueError: If the encrypted message format is incorrect or decryption fails.
    """
    try:
        # Separar nonce, ciphertext y tag del mensaje cifrado
        parts = encrypted_message.split(':')
        if len(parts) != 3:
            raise ValueError("El mensaje cifrado no tiene el formato correcto 'nonce:ciphertext:tag'.")

        # Decodificar nonce, ciphertext y tag de base64
        nonce, encrypted_data, tag = parts
        nonce = base64.b64decode(nonce)
        encrypted_data = base64.b64decode(encrypted_data)
        tag = base64.b64decode(tag)

        # Crear un objeto de cifrado AES en modo GCM utilizando la clave y el nonce
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        decryptor = cipher.decryptor()

        # Descifrar el texto cifrado y verificar la autenticidad utilizando el tag
        decryptor.authenticate_additional_data(b"")  # No hay datos adicionales
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize_with_tag(tag)

        # Devolver el texto plano decodificado
        return decrypted_data.decode()
    except ValueError as e:
        print(f"Error durante el descifrado: {e}")
        raise e


def generate_token():
    """
    Generates a 6-digit verification token.

    Returns:
        str: The generated token.
    """
    return str(random.randint(100000, 999999))


def send_token_via_email(user_email, token, mail):
    """
    Sends a verification token to the user's email.

    Args:
        user_email (str): The email address of the user.
        token (str): The verification token.
        mail (flask_mail.Mail): The Flask-Mail instance to send the email.
    """
    # Crear un mensaje con el código de verificación y enviarlo al usuario
    msg = Message('Código de verificación', recipients=[user_email])
    msg.body = f'Tu código de verificación es: {token}'
    mail.send(msg)