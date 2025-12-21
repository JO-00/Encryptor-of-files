import os

import argparse
from pathlib import Path
from Crypto.Cipher import AES
import os
import getpass


from collection_of_functions import *

KEY_SIZE = 16
NONCE_SIZE = 12

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--encrypt","-e",dest = "enc",action="store_true",help="Would you like to encrypt your files?")
    parser.add_argument("--decrypt","-d",dest = "dec",action="store_true",help="Would you like to decrypt your files?")
    parser.add_argument("--key","-k",dest = "key",type = str,help="Path to custom key file")
    parser.add_argument("-r", "--recursive", action="store_true",dest="recursive", help="Traverse all subdirectories")
    parser.add_argument("-l", "--level", type=int, help="Traverse up to N levels deep")
    parser.add_argument("-f","--forbidden",nargs = "+",dest = "Forbidden")
    parser = parser.parse_args()

    if parser.recursive and parser.level:
        raise ValueError("Either choose to go recursively with [-r/--recursive] or choose a level of recursiveness with [-l/--level]")
    
    if not(bool(parser.dec) ^ bool(parser.enc)):
        raise ValueError("Cannot Encrypt and Decrypt at the same time")

    if parser.enc and parser.enc < 0 or parser.dec and parser.dec < 0:
        raise ValueError("Can't accept negative valuesssss")

    choice = input('''
    Pick an encryption/decryption recipe:
    \tAES (Advanced Encryption Standard)
    [1] AES GCM (Most Secure for AES/DEFAULT)
    [2] AES CTR
    [3] AES CBC
    [4] AES ECB (not recommended)
    [5] AES ChaCha20_Poly1305
    \tRSA (Asymmetric Encryption)
    (Only Encrypt small files due to Computational inefficiency)
    [6] RSA PKCS1_OAEP Padding
    Example Input : the sequence 36213 means Encrypt with AES-CBC then RSA then AES-CTR then AES-GCM then AES-CBC
    ''')

    if not choice.isdecimal():
        raise ValueError("Invalid Choice")
    
    if not any(i in ["1","2","3","4","5","6"] for i in choice) :
        raise ValueError ("Digits between 1 and 6 please !")
    
    Alert = True if "6" in choice else False

    keyfile = parser.key
    password = getpass.getpass("Enter Password: ")
    if Alert and not keyfile:
        raise ValueError("You must provide a keyfile if you want RSA encryption")
    if parser.dec:
        print("Decrypting your files...")
    else:
        print("To decrypt your files: you must have:\n- The Sequence of Encryption\n- The RSA Keyfile if you chose RSA Mode '.pem'\n- Password or optionnally an AES Keyfile '.key'")
        print("Encrypting Your Files...")
        
    if Alert:
        try:
            with open(keyfile,"rb") as f:
                rsa_key = RSA.import_key(f.read())
        except Exception as e:
            print(f"Error Occured In Reading Your KeyFile: {e}")
    else:
        rsa_key = None
                           

    aes_key = key_derivation_function(password)
    
    
    
    from pathlib import Path

    # Flatten the forbidden list
    forbidden = parser.Forbidden if parser.Forbidden else []
    forbidden += [".git", Path(__file__).name, "collection_of_functions.py"]

    if parser.recursive:
        files = [
            f for f in Path(".").rglob("*")
            if f.is_file() and f.suffix != ".key"                  
            and all(i not in f.parts for i in forbidden) 
        ]
    else:
        files = get_files(".", parser.level if parser.level else 1, forbidden)

    iterate(files , choice, parser , aes_key , rsa_key if rsa_key else None , Alert)


if __name__ == '__main__':
    main()
    