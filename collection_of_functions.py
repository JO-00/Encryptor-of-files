
from Crypto.Cipher import AES
import os

KEY_SIZE = 16
NONCE_SIZE = 12




def get_files(path, depth,forbidden):
    if depth <= 0:
        return []

    entries = [entry for entry in os.scandir(path) if all([i not in entry.path for i in forbidden])]
    files = []

    for entry in entries:
        if entry.is_file():
            files.append(entry.path)
        elif entry.is_dir():
            files += get_files(entry.path, depth - 1,forbidden)

    return files


def encrypt_file(path,key):
    with open(path, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(path, "wb") as f:
        f.write(nonce + tag + ciphertext)


def decrypt_file(path,key):
    with open(path, "rb") as f:
        data = f.read()

    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE:NONCE_SIZE+16]
    ciphertext = data[NONCE_SIZE+16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    with open(path, "wb") as f:
        f.write(plaintext)


def file_type_header(data):
    
    DICT = {
        b"%PDF-"           : "pdf",
        b"\x89PNG\r\n\x1a\n": "png",
        b"\xff\xd8\xff"     : "jpeg",
        b"PK\x03\x04"       : "zip",
        b"PK\x05\x06"       : "zip",
        b"PK\x07\x08"       : "zip",
        b"OggS"             : "ogg",
        b"\x00\x00\x01\xba" : "mpeg",
        b"\x00\x00\x01\xb3" : "mpeg",
        b"GIF87a"           : "gif",
        b"GIF89a"           : "gif",
        b"Rar!\x1a\x07\x00" : "rar",
        b"Rar!\x1a\x07\x01\x00": "rar",
    }

    for magic, ftype in DICT.items():
        if data.startswith(magic):
            return ftype

    if data.startswith(b"ID3") or data[:2] == b"\xff\xfb":
        return "mp3"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav"
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "mp4"

    if all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:64]):
        return "text"
    return "binary"


def action(file, data):
    ftype = file_type_header(data)


    if ftype in ("text", "pdf", "zip"):
        return "d" if any(b < 32 or b > 126 for b in data) else "e"


    while True:
        choice = input(f"{file} is a {ftype}.\nEncrypt (e) / Decrypt (d) / Skip (s)? ").lower()
        if choice in ("e", "d", "s"):
            return choice
        print("__TRY AGAIN__")

    
def generate(given_key_path):
    chosen_keyfile = "my_key.key" if not given_key_path else given_key_path
    if os.path.exists(chosen_keyfile):
        key = open(chosen_keyfile, "rb").read()
    else:
        key = os.urandom(KEY_SIZE)
        open(chosen_keyfile, "wb").write(key)
    return chosen_keyfile


def iterate(files,parser,keyfile):
    with open(keyfile,"rb") as f:
        key = f.read()
    for file in files:
        
        enc,dec = parser.enc,parser.dec

        with open(file, "rb") as f:
        
            head = f.read(64)

        if enc:
            while (enc):
                try:
                    encrypt_file(file,key)
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
                    decrypt_file(file,key)
                    dec -=1
                except Exception:
                    print(f"Only decrypted {file} {parser.dec - dec} times")
                    break
            if not dec:
                print (f"{file} successfully decrypted {parser.dec} times")
            continue
        choice = action(file,head)
        if choice == "s":
            continue
        try:
            if choice == "d":
                print("Decrypting:", file)
                decrypt_file(file,key)
            else:
                print("Encrypting:", file)
                encrypt_file(file,key)
        except Exception as e:
            print("Failed on", file, ":", e)
