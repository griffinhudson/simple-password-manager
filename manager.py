import json
import os
import base64
import getpass
from cryptography.fernet import Fernet

DATA_FILE = 'passwords.json'
KEY_FILE = 'key.key'


def generate_key():
    """Generate and store an encryption key."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key


def load_key():
    """Load the encryption key from the key file, or create one if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()


def load_passwords():
    """Load passwords from the encrypted JSON file."""
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as file:
        encrypted_data = file.read()
        if not encrypted_data:
            return {}
        fernet = Fernet(load_key())
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data)


def save_passwords(passwords):
    """Encrypt and save passwords to the JSON file."""
    fernet = Fernet(load_key())
    encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
    with open(DATA_FILE, 'wb') as file:
        file.write(encrypted_data)


def add_password():
    """Add a new account and password."""
    account = input("Enter account name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password (hidden): ")
    passwords = load_passwords()
    passwords[account] = {'username': username, 'password': password}
    save_passwords(passwords)
    print(f"[+] Saved credentials for '{account}'")


def view_passwords():
    """View all stored passwords."""
    passwords = load_passwords()
    if not passwords:
        print("[-] No saved passwords.")
        return
    for account, creds in passwords.items():
        print(f"\n🔐 Account: {account}")
        print(f"    Username: {creds['username']}")
        print(f"    Password: {creds['password']}")


def menu():
    print("🛡️  Simple Password Manager")
    print("-----------------------------")
    print("1. Add password")
    print("2. View passwords")
    print("3. Exit")

    choice = input("Choose an option (1-3): ")

    if choice == '1':
        add_password()
    elif choice == '2':
        view_passwords()
    elif choice == '3':
        print("Exiting...")
        exit()
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    while True:
        menu()

