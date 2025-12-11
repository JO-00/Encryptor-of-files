import os

import argparse
from pathlib import Path
from Crypto.Cipher import AES
import os
from collection_of_functions import *
KEY_SIZE = 16
NONCE_SIZE = 12

keyfile = "my_key.key"




def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--encrypt","-e",dest = "enc",type=int,help="How many times would you like to encrypt every file?")
    parser.add_argument("--decrypt","-d",dest = "dec",type = int,help="How many times would you like to decrypt every file?")
    parser.add_argument("--key","-k",dest = "key",type = str,help="Path to custom key file")
    parser.add_argument("-r", "--recursive", action="store_true", help="Traverse all subdirectories")
    parser.add_argument("-l", "--level", type=int, help="Traverse up to N levels deep")
    parser.add_argument("-f","--forbidden",nargs = "+",dest = "forbidden")
    parser = parser.parse_args()

    if parser.recursive and parser.level:
        raise ValueError("Either choose to go recursively with [-r/--recursive] or choose a level of recursiveness with [-l/--level]")
    

    if parser.enc and parser.enc < 0 or parser.dec and parser.dec < 0:
        raise ValueError("Can't accept negative valuesssss")
    
    keyfile = generate(parser.key)
    forbidden = parser.forbidden + [keyfile,Path(__file__).name,"collection_of_functions.py"] if parser.forbidden else [keyfile,Path(__file__).name,"collection_of_functions.py"]

    
    if parser.recursive:
        files = [f for f in Path(".").rglob("*") if all([i not in f.parts for i in forbidden])]  
    else:
        files = get_files(".",parser.level if parser.level else 1,forbidden)

    iterate(files,parser,keyfile)


if __name__ == '__main__':
    main()
    