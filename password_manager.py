import getpass
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
from cryptography.exceptions import InvalidTag
import sys
import resource
import ctypes

class InMemoryVault:
    def __init__(self):
        self.data = {}
    def add_enrties(self, website, username, password):
        my_uuid = str(uuid.uuid4())
        dic = {"website": website, "username": username, "password": password}
        self.data[my_uuid] = dic
    def get_enrties(self):
        for key, value in self.data.items():
            print(f"ID: {key}, Website: {value['website']}, Username: {value['username']}")
    def delet_entry(self, entry_id):
        try:
            del self.data[entry_id]
            print(f"Entry with ID {entry_id} has been deleted.")
        except KeyError:
            print(f"No entry found with ID {entry_id}.")

def derive_key(master_pswd, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(master_pswd)

def encrypt_data(raw_bytes, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
    return (nonce, ciphertext)

def decrypt_data(ciphertext, key, nonce):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except InvalidTag:
        print("Decryption failed: Invalid master password or corrupted data.")
        return None

def generate_random_pasword(length=16):
    import secrets
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def manage_clipbaord(text=None):
    import subprocess
    if text:
        subprocess.run("wl-copy", universal_newlines=True, input=text)
    else:
        result = subprocess.run(["wl-copy", "-c"])
        print("\n[Security] Clipboard automatically cleared!")

def delayed_wipe():
    import time
    import threading

    def worker():
        time.sleep(20)
        manage_clipbaord(None)
    threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    MCL_CURRENT = 1
    MCL_FUTURE = 2
    try:
        libc = ctypes.CDLL("libc.so.6")
        if libc.mlockall(MCL_CURRENT | MCL_FUTURE) != 0:
            print("Warning: Failed to lock memory. Your vault may be vulnerable to swapping.")
    except Exception:
        print("Warning: Memory locking not supported or missing root privileges. Your vault may be vulnerable to swapping.")
    vault = InMemoryVault()
    if os.path.exists("vault.enc"):
        master_pswd = getpass.getpass("Enter master password to unlock your vault: ").encode("utf-8")
        with open("vault.enc", "rb") as f:
            file_content = f.read()
            salt = file_content[:16]
            nonce = file_content[16:28]
            ciphertext = file_content[28:]
            key = derive_key(master_pswd, salt)
            decrypted_data = decrypt_data(ciphertext, key, nonce)
            if decrypted_data:
                vault.data = json.loads(decrypted_data.decode("utf-8"))
                print("Vault unlocked successfully.")
            else:
                sys.exit(1)
    while True:
        print("\nPassword Vault Menu:")
        print("1. Add Entry")
        print("2. View Entries")
        print("3. Delete Entry")
        print("4. Exit")
        print("5. Copy Password to Clipboard")
        choice = input("Enter your choice: ")

        if choice == '1':
            website = input("Enter website: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password (or press [Enter] to auto-generate): ")
            if password == "":
                password = generate_random_pasword()
                print(f"Generated Password: {password}")
            vault.add_enrties(website, username, password)
            print("Entry added successfully.")

        elif choice == '2':
            vault.get_enrties()

        elif choice == '3':
            entry_id = input("Enter the ID of the entry to delete: ")
            vault.delet_entry(entry_id)

        elif choice == '5':
            vault.get_enrties()
            entry_id = input("Enter the ID of the entry to copy: ")
            entry = vault.data.get(entry_id)
            if entry:
                manage_clipbaord(entry['password'])
                delayed_wipe()
                print("Password copied to clipboard. It will be cleared in 20 seconds.")

        elif choice == '4':
            serialized_data = json.dumps(vault.data).encode("utf-8")
            master_pswd = getpass.getpass("Create a master password to encrypt your vault: ").encode("utf-8")
            salt = os.urandom(16)
            key = derive_key(master_pswd, salt)
            nonce, ciphertext = encrypt_data(serialized_data, key)
            with open("vault.enc", "wb") as f:
                f.write(salt + nonce + ciphertext)
            print("Exiting the vault. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
