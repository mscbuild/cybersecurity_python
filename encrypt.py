import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes as asymmetric_hashes
import base64

# Function to generate a secure AES key from a password
def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data using AES CBC mode
def encrypt_file(file_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    iv = os.urandom(16)  # AES requires an IV for CBC mode

    # Open file and read data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Padding the data to be multiple of AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Set up the cipher for encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Perform encryption
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted data with salt and IV at the beginning
    with open(output_path, 'wb') as f_out:
        f_out.write(salt + iv + encrypted_data)

    print(f"File encrypted successfully and saved to {output_path}")

# Function to decrypt data using AES CBC mode
def decrypt_file(encrypted_file_path: str, password: str, output_path: str):
    with open(encrypted_file_path, 'rb') as f:
        # Read the salt, iv, and encrypted data
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    # Generate the AES key from password and salt
    key = generate_key_from_password(password, salt)

    # Set up the cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Perform decryption
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted file to disk
    with open(output_path, 'wb') as f_out:
        f_out.write(unpadded_data)

    print(f"File decrypted successfully and saved to {output_path}")

# Generate RSA keys to securely encrypt the AES key (for key management)
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key

# Encrypt the AES key using RSA
def encrypt_aes_key_with_rsa(aes_key: bytes, public_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

# Decrypt the AES key using RSA
def decrypt_aes_key_with_rsa(encrypted_aes_key: bytes, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Example usage of encryption and decryption
if __name__ == "__main__":
    password = "my_secure_password"
    
    # Encrypt file
    encrypt_file('sample.txt', password, 'sample_encrypted.txt')

    # Decrypt file
    decrypt_file('sample_encrypted.txt', password, 'sample_decrypted.txt')
