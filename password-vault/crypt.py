from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import json

SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
ITERATIONS = 100000

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt(password: str, data: dict) -> str:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())

    encrypted = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return json.dumps(encrypted)

def decrypt(password: str, encrypted_data: str) -> dict:
    try:
        b = json.loads(encrypted_data)
        salt = base64.b64decode(b['salt'])
        nonce = base64.b64decode(b['nonce'])
        tag = base64.b64decode(b['tag'])
        ciphertext = base64.b64decode(b['ciphertext'])

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(decrypted.decode())
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect password or corrupt file.")
