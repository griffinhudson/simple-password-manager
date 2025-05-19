# manager.py
import getpass
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    print("=== Simple Password Manager ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    hashed = hash_password(password)
    
    with open("credentials.txt", "a") as f:
        f.write(f"{username}:{hashed}\n")
    
    print("Credentials saved (hashed for security).")

if __name__ == "__main__":
    main()
