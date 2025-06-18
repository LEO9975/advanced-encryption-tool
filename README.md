# Advanced Encryption Tool

This is a Python-based desktop GUI application designed to securely encrypt and decrypt files using industry-standard encryption algorithms. It provides a simple interface for users to protect sensitive files with a password-based key.

## 🔐 Features

- **Encryption Algorithms Supported:**
  - AES-256 (CBC mode with PKCS7 padding)
  - ChaCha20 (stream cipher without padding)
- **Secure Key Derivation:** Password-based encryption using PBKDF2 with SHA-256.
- **Cross-platform GUI:** Built with Tkinter, runs on Windows, macOS, and Linux.
- **User-friendly Interface:** Simple to use, with no command-line knowledge required.

## 📦 Requirements

- Python 3.6 or later
- `cryptography` library

Install the required package using:

```bash
pip install cryptography
