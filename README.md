# 💖 Encryptor

A Python script to encrypt and decrypt files using AES GCM mode

## 🟦 Features
- Encrypt or decrypt files multiple times
- Traverse directories recursively or to a specific depth
- Automatically skips forbidden files (keyfile or the involved scripts are considered forbidden)
- Detects file types (text, pdf, zip, etc.) and decides whether to encrypt or decrypt
- Interactive mode for choosing what to do with files

## 🟢 How to use the tool?

```bash
pip install -r requirements.txt
python encryptor.py [options]

Options:
--encrypt    -e   Number of times to encrypt each file
--decrypt    -d   Number of times to decrypt each file
--key        -k   Path to a custom key file
--recursive  -r   Traverse all subdirectories
--level      -l   Traverse up to N levels deep
--forbidden  -f   List of files or folders to skip
```
## 🔔 Limits
- This script doesn't perfectly detect extensions
- The user has to be familiar with encryption modes and provide a keyfile