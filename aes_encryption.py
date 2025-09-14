"""
AES Encryption Implementation

This module provides AES (Advanced Encryption Standard) encryption and decryption
functionality using the cryptography library. It uses AES-256 in CBC mode with
PBKDF2 key derivation and configurable security parameters.
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from validation import ValidationError


class AESEncryption:
    """AES encryption implementation for file encryption and decryption."""
    
    # Security constants - can be adjusted based on requirements
    DEFAULT_SALT_SIZE = 16      # 128 bits
    DEFAULT_IV_SIZE = 16        # 128 bits (AES block size)
    DEFAULT_ITERATIONS = 100000 # PBKDF2 iterations (OWASP recommended minimum)
    KEY_SIZE = 32              # 256 bits for AES-256
    
    def __init__(self, password, iterations=None, salt_size=None, iv_size=None):
        """
        Initialize AES encryption with a password and optional security parameters.
        
        Args:
            password (str): Password for key derivation
            iterations (int): PBKDF2 iterations (default: 100,000)
            salt_size (int): Salt size in bytes (default: 16)
            iv_size (int): IV size in bytes (default: 16)
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(password, str):
            raise ValidationError("Password must be a string")
        
        if len(password.encode('utf-8')) == 0:
            raise ValidationError("Password cannot be empty")
        
        self.password = password.encode('utf-8')
        self.backend = default_backend()
        
        # Configure security parameters
        self.iterations = iterations or self.DEFAULT_ITERATIONS
        self.salt_size = salt_size or self.DEFAULT_SALT_SIZE
        self.iv_size = iv_size or self.DEFAULT_IV_SIZE
        
        # Validate parameters
        if self.iterations < 10000:
            raise ValidationError(
                f"PBKDF2 iterations too low: {self.iterations}. "
                "Minimum recommended: 10,000 (prefer 100,000+)"
            )
        
        if self.salt_size < 8:
            raise ValidationError(f"Salt size too small: {self.salt_size} bytes (minimum: 8)")
        
        if self.iv_size != 16:
            raise ValidationError(f"IV size must be 16 bytes for AES, got: {self.iv_size}")
    
    def _derive_key(self, salt):
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: Derived key
            
        Raises:
            ValidationError: If salt is invalid
        """
        if not isinstance(salt, bytes):
            raise ValidationError("Salt must be bytes")
        
        if len(salt) != self.salt_size:
            raise ValidationError(f"Salt size mismatch: expected {self.salt_size}, got {len(salt)}")
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=self.iterations,
                backend=self.backend
            )
            return kdf.derive(self.password)
        except Exception as e:
            raise ValidationError(f"Key derivation failed: {str(e)}")
    
    def encrypt_data(self, data):
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data with salt and IV prepended
            
        Raises:
            ValidationError: If data is invalid or encryption fails
        """
        if not isinstance(data, bytes):
            raise ValidationError("Data to encrypt must be bytes")
        
        try:
            # Generate random salt and IV
            salt = os.urandom(self.salt_size)
            iv = os.urandom(self.iv_size)
            
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
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_data):
        """
        Decrypt data using AES-256-CBC.
        
        Args:
            encrypted_data (bytes): Encrypted data with salt and IV
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            ValidationError: If data is invalid or decryption fails
        """
        if not isinstance(encrypted_data, bytes):
            raise ValidationError("Encrypted data must be bytes")
        
        min_size = self.salt_size + self.iv_size
        if len(encrypted_data) < min_size:
            raise ValidationError(
                f"Invalid encrypted data: too short. "
                f"Expected at least {min_size} bytes (salt + IV), got {len(encrypted_data)}"
            )
        
        try:
            # Extract salt, IV, and encrypted data
            salt = encrypted_data[:self.salt_size]
            iv = encrypted_data[self.salt_size:self.salt_size + self.iv_size]
            ciphertext = encrypted_data[self.salt_size + self.iv_size:]
            
            if len(ciphertext) == 0:
                raise ValidationError("No ciphertext found in encrypted data")
            
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
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            # Provide more specific error messages
            if "padding" in str(e).lower():
                raise ValidationError(
                    "Decryption failed: Invalid padding. "
                    "This usually means wrong password or corrupted data."
                )
            elif "authentication" in str(e).lower() or "mac" in str(e).lower():
                raise ValidationError("Decryption failed: Authentication error (wrong password)")
            else:
                raise ValidationError(f"Decryption failed: {str(e)}")
    
    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file using AES encryption.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
            
        Raises:
            ValidationError: If file operations fail
        """
        from validation import validate_file_path
        
        # Validate input file
        input_path = validate_file_path(input_path, check_exists=True, check_readable=True)
        output_path = validate_file_path(output_path, check_exists=False, check_writable=True)
        
        try:
            # Read input file
            with open(input_path, 'rb') as infile:
                data = infile.read()
            
            # Encrypt data
            encrypted_data = self.encrypt_data(data)
            
            # Write encrypted data to output file
            with open(output_path, 'wb') as outfile:
                outfile.write(encrypted_data)
                
        except PermissionError as e:
            raise ValidationError(f"Permission denied: {str(e)}")
        except OSError as e:
            raise ValidationError(f"File system error: {str(e)}")
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, input_path, output_path):
        """
        Decrypt a file using AES decryption.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
            
        Raises:
            ValidationError: If file operations fail
        """
        from validation import validate_file_path
        
        # Validate input file
        input_path = validate_file_path(input_path, check_exists=True, check_readable=True)
        output_path = validate_file_path(output_path, check_exists=False, check_writable=True)
        
        try:
            # Read encrypted file
            with open(input_path, 'rb') as infile:
                encrypted_data = infile.read()
            
            if len(encrypted_data) == 0:
                raise ValidationError("Input file is empty")
            
            # Decrypt data
            decrypted_data = self.decrypt_data(encrypted_data)
            
            # Write decrypted data to output file
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
                
        except PermissionError as e:
            raise ValidationError(f"Permission denied: {str(e)}")
        except OSError as e:
            raise ValidationError(f"File system error: {str(e)}")
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"File decryption failed: {str(e)}")


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
