# 🔐 Simple Password Manager

A command-line password manager built in Python that securely stores login credentials using encryption (via the `cryptography` library). All passwords are encrypted and saved locally.

## Features

- AES encryption using Fernet (`cryptography` library)
- Locally stores passwords in an encrypted JSON file (`passwords.json`)
- Automatically generates and securely stores an encryption key (`key.key`)
- Terminal interface to:
  - Add new credentials
  - View saved credentials (decrypted)
- Cross-platform (Windows, macOS, Linux)

## Requirements

- Python 3.7+
- `cryptography` library

Install dependencies:

```bash
pip install cryptography

## Security Fix

Previous versions stored the encryption key in plaintext (`key.key`), which is insecure if exposed. The latest update:

- Removes static key storage.
- Uses PBKDF2 to derive the encryption key from a master password.
- Stores only a `salt.bin` file (safe to ignore on GitHub).
- Improves overall password manager security.

Ensure you do not upload `passwords.json` or `salt.bin` to GitHub.
