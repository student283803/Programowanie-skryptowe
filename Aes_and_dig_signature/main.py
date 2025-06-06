from AES_encryption import encryption

file_to_encrypt = "data.txt"
encrypted_file = "encrypted_data.bin"
key_file = "key_file.bin"
nonce_file = "nonce.bin"
tag_file = "tag.bin"
key_size_bytes: int = 32

encryption(
    file_to_encrypt,
    encrypted_file,
    key_file,
    nonce_file,
    tag_file)