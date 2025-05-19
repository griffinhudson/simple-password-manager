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
