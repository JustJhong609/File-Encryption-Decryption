"""
AES Encryption Implementation

This module provides AES (Advanced Encryption Standard) encryption and decryption
functionality using the cryptography library. It uses AES-256 in CBC mode with
PBKDF2 key derivation.
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESEncryption:
    """AES encryption implementation for file encryption and decryption."""
    
    def __init__(self, password):
        """
        Initialize AES encryption with a password.
        
        Args:
            password (str): Password for key derivation
        """
        self.password = password.encode('utf-8')
        self.backend = default_backend()
    
    def _derive_key(self, salt):
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 key length
            salt=salt,
            iterations=100000,  # Recommended minimum iterations
            backend=self.backend
        )
        return kdf.derive(self.password)
    
    def encrypt_data(self, data):
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data with salt and IV prepended
        """
        # Generate random salt and IV
        salt = os.urandom(16)  # 16 bytes salt
        iv = os.urandom(16)    # 16 bytes IV for AES
        
        # Derive key from password and salt
        key = self._derive_key(salt)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return salt + IV + encrypted data
        return salt + iv + encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """
        Decrypt data using AES-256-CBC.
        
        Args:
            encrypted_data (bytes): Encrypted data with salt and IV
            
        Returns:
            bytes: Decrypted data
        """
        if len(encrypted_data) < 32:  # Salt (16) + IV (16) minimum
            raise ValueError("Invalid encrypted data: too short")
        
        # Extract salt, IV, and encrypted data
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Derive key from password and salt
        key = self._derive_key(salt)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        
        return data
    
    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file using AES encryption.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
        """
        # Read input file
        with open(input_path, 'rb') as infile:
            data = infile.read()
        
        # Encrypt data
        encrypted_data = self.encrypt_data(data)
        
        # Write encrypted data to output file
        with open(output_path, 'wb') as outfile:
            outfile.write(encrypted_data)
    
    def decrypt_file(self, input_path, output_path):
        """
        Decrypt a file using AES decryption.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
        """
        # Read encrypted file
        with open(input_path, 'rb') as infile:
            encrypted_data = infile.read()
        
        # Decrypt data
        decrypted_data = self.decrypt_data(encrypted_data)
        
        # Write decrypted data to output file
        with open(output_path, 'wb') as outfile:
            outfile.write(decrypted_data)


def demo_aes():
    """Demonstrate AES encryption functionality."""
    print("=== AES Encryption Demo ===")
    
    # Create AES encryption instance
    password = "demo_password_123"
    aes = AESEncryption(password)
    
    # Test data encryption
    original_data = b"Hello, World! This is a test message for AES encryption."
    encrypted_data = aes.encrypt_data(original_data)
    decrypted_data = aes.decrypt_data(encrypted_data)
    
    print(f"Original:  {original_data}")
    print(f"Encrypted: {base64.b64encode(encrypted_data).decode()}")
    print(f"Decrypted: {decrypted_data}")
    print(f"Match: {original_data == decrypted_data}")


if __name__ == "__main__":
    demo_aes()
