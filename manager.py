from cryptography.fernet import Fernet
import os
import base64
import hashlib
from getpass import getpass

# File to store passwords
DATA_FILE = 'passwords.txt'
KEY_FILE = 'key.key'


def generate_key(master_password):
    """Derive a Fernet key from the master password."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(master_password.encode()).digest()
    )


def load_key():
    """Load the encryption key from file, or prompt user to create it."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as file:
            return file.read()
    else:
        print("No key found. Creating a new one...")
        master_pwd = getpass("Set a master password: ")
        key = generate_key(master_pwd)
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
        return key


def add_password(fernet):
    site = input("Enter website name: ")
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    encrypted = fernet.encrypt(f"{site}|{username}|{password}".encode()).decode()
    with open(DATA_FILE, 'a') as f:
        f.write(encrypted + '\n')
    print("✅ Password added successfully!\n")


def view_passwords(fernet):
    if not os.path.exists(DATA_FILE):
        print("No passwords saved yet.\n")
        return

    with open(DATA_FILE, 'r') as f:
        lines = f.readlines()
        if not lines:
            print("No passwords found.\n")
            return

        print("\n🔐 Saved Passwords:\n")
        for line in lines:
            try:
                decrypted = fernet.decrypt(line.strip().encode()).decode()
                site, username, password = decrypted.split('|')
                print(f"🌐 Site: {site}\n👤 Username: {username}\n🔑 Password: {password}\n")
            except Exception:
                print("⚠️ Could not decrypt a line. Skipping...\n")


def main():
    print("🔐 Welcome to the Secure Password Manager!")
    master_pwd = getpass("Enter your master password: ")
    key = generate_key(master_pwd)

    # Verify that key matches the stored key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            stored_key = f.read()
        if stored_key != key:
            print("❌ Incorrect master password!")
            return

    fernet = Fernet(key)

    while True:
        print("1. Add a new password")
        print("2. View saved passwords")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_password(fernet)
        elif choice == '2':
            view_passwords(fernet)
        elif choice == '3':
            print("Goodbye! 👋")
            break
        else:
            print("Invalid choice. Try again.\n")


if __name__ == '__main__':
    main()
