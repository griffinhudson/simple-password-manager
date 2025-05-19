import json
import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

DATA_FILE = 'passwords.json'
SALT_FILE = 'salt.bin'
ITERATIONS = 390000  # Recommended minimum for PBKDF2


def get_master_password():
    return getpass.getpass("Enter master password: ").encode()


def generate_salt():
    salt = os.urandom(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt


def load_salt():
    if not os.path.exists(SALT_FILE):
        return generate_salt()
    with open(SALT_FILE, 'rb') as f:
        return f.read()


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def load_passwords(fernet):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        encrypted_data = file.read()
        if not encrypted_data:
            return {}
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception:
            print("❌ Incorrect master password or corrupted data.")
            exit()


def save_passwords(passwords, fernet):
    encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
    with open(DATA_FILE, 'wb') as file:
        file.write(encrypted_data)


def add_password(fernet):
    account = input("Enter account name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password (hidden): ")
    passwords = load_passwords(fernet)
    passwords[account] = {'username': username, 'password': password}
    save_passwords(passwords, fernet)
    print(f"[+] Saved credentials for '{account}'")


def view_passwords(fernet):
    passwords = load_passwords(fernet)
    if not passwords:
        print("[-] No saved passwords.")
        return
    for account, creds in passwords.items():
        print(f"\n🔐 Account: {account}")
        print(f"    Username: {creds['username']}")
        print(f"    Password: {creds['password']}")


def menu(fernet):
    print("🛡️  Simple Password Manager")
    print("-----------------------------")
    print("1. Add password")
    print("2. View passwords")
    print("3. Exit")

    choice = input("Choose an option (1-3): ")

    if choice == '1':
        add_password(fernet)
    elif choice == '2':
        view_passwords(fernet)
    elif choice == '3':
        print("Exiting...")
        exit()
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    password = get_master_password()
    salt = load_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)

    while True:
        menu(fernet)
