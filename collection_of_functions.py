
from Crypto.Cipher import PKCS1_OAEP,ChaCha20_Poly1305,AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter
from Crypto.Hash import SHA512
import os

import time




SALT = b"\x69"*16

BLOCK_SIZE = 16

KEY_SIZE = 16
NONCE_SIZE = 12
IV_SIZE = 16

class EncryptionStack:
    def __init__(self):
        self.stack = []
    def push(self,value):
        self.stack.append(value)
    def pop(self):
        if len(self.stack) == 0:
            return
        return self.stack.pop()
    def peek(self):
        return None if not self.stack else self.stack[-1]
    def __repr__(self):#To debuggg
        print(self.stack) 


key_derivation_function = lambda password : PBKDF2(password, SALT, 64, count=1000000, hmac_hash_module=SHA512)[:16]
    
def prepare_stack(Sequence,aes_key,rsa_key,Alert):
    if bool(rsa_key)^Alert:
        return []
        
    stack = EncryptionStack()
    for i in Sequence:
        algorithm = ["aes"] if i != "6" else "rsa"

        match i:
            case "1":
                helper,cipher = None,None # If we encrypt more than one time, counter will increment instead of being initialized to zero
                algorithm.append("gcm")
            case "2":
                helper,cipher = None,None #same issue as gcm
                algorithm.append("ctr")

            case "3":
                iv = os.urandom(BLOCK_SIZE)
                cipher = AES.new(aes_key,AES.MODE_CBC,iv=iv) #only useful during encryption
                helper = iv
                algorithm.append("cbc")
            case "4":
                cipher = AES.new(aes_key,AES.MODE_ECB)
                helper = None
                algorithm.append("ecb")
            case "5":
                helper,cipher = None,None #Same issue as gcm
                algorithm.append("chacha20")
            case "6":
                cipher = PKCS1_OAEP.new(rsa_key)
                helper = None

        
        stack.push((algorithm,cipher,helper))
    
    return stack

def encrypt_file(path, encryption_stack, aes_key):
    with open(path, "rb") as f:
        entry = f.read()
    def one_time_encryption(entry, algorithm, cipher_object, helper):
        if entry is None:
            raise ValueError(f"File {path} returned None during encryption step")
        if algorithm == "rsa":
            return cipher_object.encrypt(entry)
        mode = algorithm[1]
        match mode:
            case "ecb":
                entry = pad(entry, BLOCK_SIZE)
                return cipher_object.encrypt(entry)

            case "cbc":
                entry = pad(entry, BLOCK_SIZE)
                # prepend IV to ciphertext
                return helper + cipher_object.encrypt(entry)

            case "ctr":
                nonce = get_random_bytes(NONCE_SIZE)
                ctr = Counter.new((BLOCK_SIZE - NONCE_SIZE) * 8, prefix=nonce)
                return nonce + AES.new(aes_key, AES.MODE_CTR, counter=ctr).encrypt(entry)

            case "gcm":
                cipher = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(entry)
                return cipher.nonce + ciphertext + tag


            case "chacha20":
                cipher = ChaCha20_Poly1305.new(key=aes_key*2)
                ciphertext, tag = cipher.encrypt_and_digest(entry)
                return cipher.nonce + ciphertext + tag


        

            case _:
                raise ValueError(f"Unknown mode: {mode}")

    while encryption_stack.peek() is not None:
        node = encryption_stack.pop()
        if node[0] == "rsa" and len(entry) > 200:
            print(f"will not encrypt {path}, exceeds size limit for rsa encryption!")
            return
        
        entry = one_time_encryption(entry, *node)
    with open(path, "wb") as f:
        f.write(entry)


def decrypt_file(path, encryption_stack, aes_key):
    with open(path, "rb") as f:
        entry = f.read()
    print(f"working on {path}")
    def one_time_decryption(entry, algorithm, cipher_object, helper):
        if entry is None:
            raise ValueError(f"File {path} returned None during encryption step")
        if algorithm == "rsa":
            return cipher_object.decrypt(entry)
        mode = algorithm[1]
        match mode:
            case "ecb":
                entry = cipher_object.decrypt(entry)
                return unpad(entry, BLOCK_SIZE)

            case "cbc":
                iv = entry[:BLOCK_SIZE]
                ciphertext = entry[BLOCK_SIZE:]
                return unpad(AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ciphertext), BLOCK_SIZE)

            case "ctr":
                nonce = entry[:NONCE_SIZE]
                ciphertext = entry[NONCE_SIZE:]
                ctr = Counter.new((BLOCK_SIZE - NONCE_SIZE) * 8, prefix=nonce)
                return AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(ciphertext)

            case "gcm":
                nonce_len = len(helper) if helper else 16  # take helper if available
                nonce = entry[:nonce_len]
                ciphertext = entry[nonce_len:-16]
                tag = entry[-16:]
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag)

            case "chacha20":
                nonce = entry[:NONCE_SIZE]
                ciphertext = entry[NONCE_SIZE:-16]
                tag = entry[-16:]
                return ChaCha20_Poly1305.new(key=aes_key*2, nonce=nonce).decrypt_and_verify(ciphertext, tag)

            case _:
                raise ValueError(f"Unknown mode: {mode}")

    while encryption_stack.peek() is not None:
        node = encryption_stack.pop()
        entry = one_time_decryption(entry, *node)

    with open(path, "wb") as f:
        f.write(entry)
        
def get_files(path, depth, forbidden):
    if depth <= 0:
        return []

    entries = [
        entry for entry in os.scandir(path)
        if all(f not in entry.path for f in forbidden)
           and not entry.name.lower().endswith(".key")  # case-insensitive
    ]
    files = []

    for entry in entries:
        if entry.is_file():
            files.append(entry.path)
        elif entry.is_dir():
            files += get_files(entry.path, depth - 1, forbidden)

    return files

def iterate(files, Sequence ,parser,aes_key,rsa_key,Alert):
    enc = parser.enc
    if enc:
        
        for file in files:
            encryption_stack = prepare_stack(Sequence,aes_key,rsa_key,Alert)
            try:
                encrypt_file(file,encryption_stack,aes_key)
                print(f"file {file} encrypted successfully")
            except Exception as e:
                print(f'file {file} caused exception : {e}')
            

    else:
        
        for file in files:
            encryption_stack = prepare_stack(Sequence[::-1],aes_key,rsa_key,Alert)
            try:
                decrypt_file(file,encryption_stack,aes_key)
                print(f"file {file} encrypted successfully")
            except Exception as e:
                print(f'file {file} caused exception : {e}')


