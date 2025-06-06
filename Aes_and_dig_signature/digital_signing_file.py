import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def generate_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    if os.path.exists(private_key_path) or os.path.exists(public_key_path):
        print("Private key and public key file already exists")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"Private key created in '{private_key_path}'")

    public_key = private_key.public_key()

    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Public key created in '{public_key_path}'")

def sign_file(file_path, private_key_path, signature_path = "signature.sig"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(file_path, "rb") as file:
        file_data = file.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    with open(signature_path, "wb") as file:
        file.write(signature)
    print(f"Signature created in '{signature_path}', File '{file_path}' was signed")


def verify_signature(file_path, signature_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    with open(file_path, "rb") as file:
        file_data = file.read()
    with open(signature_path, "rb") as file:
        signature = file.read()

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("Signature verified")
        return True
    except Exception as e:
        print("Signature verification failed")
        print(e)
        return False


