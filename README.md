# 💖 Encryptor

A Python script to encrypt and decrypt files, for **Decryption** you'd need the same **Sequence** and **Password** you've entered during Encryption

## 🟦 Features
- Encrypt or decrypt files using a sequence of algorithms (e.g., AES → RSA → AES)
- Supports AES (GCM, CTR, CBC, ECB), ChaCha20-Poly1305, and RSA PKCS1_OAEP
- Traverse directories recursively or up to a specific depth
- Automatically skips forbidden files and directories (.git, key files, script files, etc...)
- Interactive mode to select the encryption/decryption sequence
- Password-based AES key derivation using PBKDF2 with SHA-512 (1,000,000 iterations)
- Protects against encrypting files too large for RSA

## 🟢 How to use the tool?

```bash
git clone https://github.com/JO-00/Encryptor-of-files
cd Encryptor-of-files

pip install -r requirements.txt
python encryptor.py [options]

Options:
--encrypt    -e   Whether You're willing to Encrypt
--decrypt    -d   Whether You're willing to Decrypt
--key        -k   Path to a custom RSA keyfile
--recursive  -r   Traverse all subdirectories
--level      -l   Traverse up to N levels deep
--forbidden  -f   List of files or folders to skip
```
## 💥 Strengths
> **Brute-forcing password or sequence is computationally expensive by design to prevent Attacks.**
>
>**More User-Friendly now since only password has to be provided for AES encryption**



## ⚠️ Warnings
- Sequence must be remembered exactly; wrong order or missing steps prevents decryption and causes data loss
- This script no longer works on Extensions, all files of any extension are encrypted
- If the User wants to use RSA, he must provide an RSA keyfile
- Not intended for production-level security; a learning and experimentation tool
