# 🔐 Simple Password Manager

A command-line password manager built in Python that securely stores login credentials using AES encryption (via the `cryptography` library). Access is protected by a master password, and all passwords are encrypted and saved locally.

## Features

- AES-256 encryption with Fernet (from `cryptography`)
- Passwords saved securely in an encrypted file
- Requires a master password for access
- Simple terminal menu to add and view credentials
- Cross-platform (Windows, macOS, Linux)

## Requirements

- Python 3.7+
- `cryptography` library

Install dependencies:

```bash
pip install cryptography
