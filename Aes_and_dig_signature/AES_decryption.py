from Crypto.Cipher import AES
import os

def decryption (
        encrypted_file: str,
        key_file: str,
        nonce_file: str,
        tag_file: str,
        decrypted_file: str,
):
    with open(key_file, "rb") as key_file:
        key = key_file.read()
    with open(nonce_file, "rb") as nonce_file:
        nonce = nonce_file.read()
    with open(tag_file, "rb") as tag_file:
        tag = tag_file.read()
    with open(encrypted_file, "rb") as encrypted_file:
        encrypted = encrypted_file.read()

#decipher

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext_bytes = cipher.decrypt_and_verify(encrypted, tag)

        with open(decrypted_file, "wb") as decrypted_file:
            decrypted = decrypted_file.write(plaintext_bytes)

            print(f"dane zostaly odszyfrowane i zapisane w pliku {decrypted_file}")
    except (ValueError, KeyError) as e:
        print ("blad deszyfrowania")



