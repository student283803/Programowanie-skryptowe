from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
import os

def encryption(
        file_to_encrypt: str,
        encrypted_file: str,
        key_file: str,
        nonce_file: str,
        tag_file: str,
        key_size_bytes: int = 32
):

    #generate key
    print ("generowanie klucza...")
    key = get_random_bytes(key_size_bytes)
    with open (key_file, "wb") as key_file:
        key_file.write(key)

    #load data
    print("wczytywanie danych...")
    with open(file_to_encrypt, mode='rb') as file:
        plaintext = file.read()

    #encrypt data
    print ("szyfrowanie danych...")
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    with open (encrypted_file, "wb") as encrypted_file:
        encrypted_file.write(ciphertext)
    print (f"zaszyfrowane dane zapisano do pliku {encrypted_file}")

    with open (nonce_file, "wb") as nonce_file:
        nonce_file.write(nonce)
    print (f"Nonce zapisano do pliku {nonce_file}")

    with open (tag_file, "wb") as tag_file:
        tag_file.write(tag)
    print (f"Tag zapisano do pliku {tag_file}")
