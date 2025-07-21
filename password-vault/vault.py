import os
import json
import base64
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

VAULT_FILE = "vault.json"
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits
ITERATIONS = 100_000

def derive_key(master_password, salt):
    return PBKDF2(master_password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_data(key, enc_data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(enc_data["nonce"]))
    return cipher.decrypt_and_verify(
        base64.b64decode(enc_data["ciphertext"]),
        base64.b64decode(enc_data["tag"])
    ).decode()

def load_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "r") as f:
        encrypted = json.load(f)
    salt = base64.b64decode(encrypted["salt"])
    enc_data = encrypted["data"]
    return json.loads(decrypt_data(derive_key(master_password, salt), enc_data))

def save_vault(key, vault_data, salt):
    data = json.dumps(vault_data)
    encrypted = encrypt_data(key, data)
    with open(VAULT_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "data": encrypted
        }, f)

# === Main ===
master_password = getpass.getpass("Enter master password: ")

if os.path.exists(VAULT_FILE):
    with open(VAULT_FILE, "r") as f:
        existing = json.load(f)
    salt = base64.b64decode(existing["salt"])
else:
    salt = get_random_bytes(SALT_SIZE)

key = derive_key(master_password, salt)

try:
    vault = load_vault(key)
except Exception as e:
    print("Invalid master password or corrupted vault.")
    exit(1)

while True:
    cmd = input("Enter command (add/get/list/delete/exit): ").strip().lower()
    if cmd == "add":
        name = input("Entry name: ")
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        vault[name] = {"username": username, "password": password}
        save_vault(key, vault, salt)
        print("Saved.")
    elif cmd == "get":
        name = input("Entry name: ")
        if name in vault:
            print(f"Username: {vault[name]['username']}")
            print(f"Password: {vault[name]['password']}")
        else:
            print("Not found.")
    elif cmd == "list":
        for name in vault:
            print(f"- {name}")
    elif cmd == "delete":
        name = input("Entry name to delete: ")
        if name in vault:
            del vault[name]
            save_vault(key, vault, salt)
            print("Deleted.")
        else:
            print("Not found.")
    elif cmd == "exit":
        break
    else:
        print("Invalid command.")
