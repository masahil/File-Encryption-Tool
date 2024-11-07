from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Functions for generating a PBKDF2-derived key
def generate_pbkdf2_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_with_aes(filename, key):
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(filename, "rb") as file:
        file_data = file.read()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(filename, "wb") as file:
        file.write(iv + encrypted_data)

def decrypt_with_aes(filename, key):
    backend = default_backend()
    with open(filename, "rb") as file:
        file_data = file.read()
        iv = file_data[:16]
        encrypted_data = file_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(filename, "wb") as file:
        file.write(unpadded_data)

def main():
    choice = input("Enter 'E' to encrypt or 'D' to decrypt the file: ").lower()
    if choice == 'e':
        filename = input("Enter the file name to encrypt (including file extension): ")
        if os.path.exists(filename):
            pbkdf2_key = generate_pbkdf2_key("your_password", b'salt_here')
            encrypt_with_aes(filename, pbkdf2_key)
            print("File Encrypted Successfully!!!")
        else:
            print(f"File '{filename}' not found. Please check the file name and try again.")
    elif choice == "d":
        filename = input("Enter the file name to decrypt (including file extension): ")
        if os.path.exists(filename):
            pbkdf2_key = generate_pbkdf2_key("your_password", b'salt_here')
            decrypt_with_aes(filename, pbkdf2_key)
            print("File Decrypted Successfully!!!")
        else:
            print(f"File '{filename}' not found. Please check the file name and try again.")
    else:
        print("Invalid choice. Please enter 'E' to encrypt a file or 'D' to decrypt a file.")

if __name__ == "__main__":
    main()
