from AES_encryption import encryption
from AES_decryption import decryption
import digital_signing_file as dsf

def main():
    file_to_encrypt = input("Enter the file to encrypt: ")
    decrypted_file = "decrypted_data.txt"
    encrypted_file = "encrypted_data.bin"
    key_file = "key_file.bin"
    nonce_file = "nonce.bin"
    tag_file = "tag.bin"
    file_to_sign = input("Enter the file to sign: ")
    private_key_file = "private_key_file.pem"
    public_key_file = "public_key_file.pem"
    signature_file = "signature.sig"

    encryption(
        file_to_encrypt,
        encrypted_file,
        key_file,
        nonce_file,
        tag_file)

    decryption(
        encrypted_file,
        key_file,
        nonce_file,
        tag_file,
        decrypted_file
    )

    dsf.generate_keys(private_key_file, public_key_file)
    dsf.sign_file(file_to_sign, private_key_file, signature_file)
    dsf.verify_signature(file_to_sign, signature_file, public_key_file)

    print ("test - modyfikacja pliku i weryfikacja")

    with open (file_to_sign, "a", encoding="utf-8") as file:
        file.write("\nTa linijka narusza integralnosc")

    print("ponowna weryfkacja:")
    dsf.verify_signature(signature_file,file_to_sign, public_key_file)

if __name__ == "__main__":
    main()
