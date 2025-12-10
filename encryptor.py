import os
from Crypto.Cipher import AES
import argparse







KEY_SIZE = 16
NONCE_SIZE = 12

keyfile = "my_key.key"



def encrypt_file(path):
    with open(path, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(path, "wb") as f:
        f.write(nonce + tag + ciphertext)

def decrypt_file(path):
    with open(path, "rb") as f:
        data = f.read()

    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE:NONCE_SIZE+16]
    ciphertext = data[NONCE_SIZE+16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(path, "wb") as f:
        f.write(plaintext)

looks_encrypted = lambda data : any([i not in range(32,127) for i in data ])

def generate():
    if os.path.exists(keyfile):
        key = open(keyfile, "rb").read()
    else:
        key = os.urandom(KEY_SIZE)
        open(keyfile, "wb").write(key)
    return key


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--encrypt","-e",dest = "enc",type=int)
    parser.add_argument("--decrypt","-d",dest = "dec",type = int)
    parser = parser.parse_args()
    if parser.enc and parser.enc < 0 or parser.dec and parser.dec < 0:
        raise ValueError("Can't accept negative values !")

    key = generate()



    files = [file for file in os.listdir() if file not in [os.path.basename(__file__) , keyfile] and os.path.isfile(file)]
    
    for file in files:
        enc,dec = parser.enc,parser.dec

        with open(file, "rb") as f:
        
            head = f.read(64)

        if enc:
            while (enc):
                try:
                    encrypt_file(file)
                    enc -=1
                except Exception:
                    print(f"Only encrypted {file} {parser.enc - enc} times")
                    break
            if not enc:
                print (f"{file} successfully encrypted {parser.enc} times")
            continue
        if dec:
            while (dec):
                try:
                    decrypt_file(file)
                    dec -=1
                except Exception:
                    print(f"Only decrypted {file} {parser.dec - dec} times")
                    break
            if not dec:
                print (f"{file} successfully decrypted {parser.dec} times")
            continue

        try:
            if looks_encrypted(head):
                print("Decrypting:", file)
                decrypt_file(file)
            else:
                print("Encrypting:", file)
                encrypt_file(file)
        except Exception as e:
            print("Failed on", file, ":", e)
