"""
AES Encryption Implementation

This module provides AES (Advanced Encryption Standard) encryption and decryption
functionality using the cryptography library. Supports both CBC mode (compatibility)
and GCM mode (authenticated encryption) with PBKDF2 key derivation and configurable
security parameters. Implements chunked processing for memory efficiency.
"""

import os
import gc
import base64
import logging
import time
from pathlib import Path
from typing import Union, Optional, Tuple, Iterator, BinaryIO
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from validation import ValidationError
from error_handling import (
    EncryptionError, DecryptionError, AuthenticationError,
    FileOperationError, validate_file_access, log_operation_start,
    log_operation_complete, handle_corrupted_file, handle_invalid_decryption_key
)


class AESEncryption:
    """
    AES encryption implementation supporting both CBC and GCM modes.
    
    Features:
    - AES-256 encryption in CBC or GCM mode
    - PBKDF2 key derivation with configurable parameters
    - Chunked processing for memory efficiency with large files
    - Comprehensive error handling and logging
    - Memory security (best-effort password clearing)
    """
    
    # Security constants - can be adjusted based on requirements
    DEFAULT_SALT_SIZE: int = 16          # 128 bits
    DEFAULT_IV_SIZE: int = 16            # 128 bits (AES block size)
    DEFAULT_NONCE_SIZE: int = 12         # 96 bits (recommended for GCM)
    DEFAULT_ITERATIONS: int = 100000     # PBKDF2 iterations (OWASP recommended minimum)
    KEY_SIZE: int = 32                   # 256 bits for AES-256
    CHUNK_SIZE: int = 64 * 1024          # 64KB chunks for file processing
    GCM_TAG_SIZE: int = 16              # 128 bits authentication tag
    
    def __init__(
        self, 
        password: str, 
        iterations: Optional[int] = None, 
        salt_size: Optional[int] = None,
        use_gcm: bool = True,
        logger: Optional[logging.Logger] = None,
        testing_mode: bool = False
    ) -> None:
        """
        Initialize AES encryption with a password and optional security parameters.
        
        Args:
            password: Password for key derivation
            iterations: PBKDF2 iterations (default: 100,000)
            salt_size: Salt size in bytes (default: 16)
            use_gcm: Use AES-GCM for authenticated encryption (default: True)
            logger: Optional logger instance
            testing_mode: If True, don't clear password automatically (for testing)
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not isinstance(password, str):
            raise ValidationError("Password must be a string")
        
        if len(password.encode('utf-8')) == 0:
            raise ValidationError("Password cannot be empty")
        
        # Store password temporarily (will be cleared after key derivation)
        self._password = password.encode('utf-8')
        self.backend = default_backend()
        self.logger = logger or logging.getLogger(__name__)
        self.testing_mode = testing_mode
        
        # Configure security parameters
        self.iterations = iterations or self.DEFAULT_ITERATIONS
        self.salt_size = salt_size or self.DEFAULT_SALT_SIZE
        self.use_gcm = use_gcm
        
        # Validate parameters
        self._validate_parameters()
        
        # Log configuration
        self.logger.debug(f"AES encryption initialized:")
        self.logger.debug(f"  Mode: {'GCM' if use_gcm else 'CBC'}")
        self.logger.debug(f"  Iterations: {self.iterations:,}")
        self.logger.debug(f"  Salt size: {self.salt_size} bytes")
    
    def _validate_parameters(self) -> None:
        """Validate initialization parameters."""
        if self.iterations < 10000:
            raise ValidationError(
                f"PBKDF2 iterations too low: {self.iterations}. "
                "Minimum recommended: 10,000 (prefer 100,000+)"
            )
        
        if self.salt_size < 8:
            raise ValidationError(f"Salt size too small: {self.salt_size} bytes (minimum: 8)")
    
    def __del__(self) -> None:
        """Clear sensitive data on object destruction."""
        if not getattr(self, 'testing_mode', False):
            self._clear_password()
    
    def _clear_password(self) -> None:
        """Best-effort clearing of password from memory."""
        try:
            if hasattr(self, '_password') and self._password:
                # Overwrite password bytes with zeros
                password_array = bytearray(self._password)
                for i in range(len(password_array)):
                    password_array[i] = 0
                self._password = bytes(password_array)
                del self._password
                gc.collect()  # Encourage garbage collection
        except Exception:
            pass  # Ignore errors during cleanup
    
    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            salt: Salt for key derivation
            
        Returns:
            Derived encryption key
            
        Raises:
            ValidationError: If salt is invalid
            EncryptionError: If key derivation fails
        """
        if not isinstance(salt, bytes):
            raise ValidationError("Salt must be bytes")
        
        if len(salt) != self.salt_size:
            raise ValidationError(f"Salt size mismatch: expected {self.salt_size}, got {len(salt)}")
        
        if not hasattr(self, '_password') or not self._password:
            raise EncryptionError("Password has been cleared from memory")
        
        try:
            self.logger.debug(f"Deriving key with {self.iterations:,} iterations")
            start_time = time.time()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=self.iterations,
                backend=self.backend
            )
            key = kdf.derive(self._password)
            
            elapsed = time.time() - start_time
            self.logger.debug(f"Key derivation completed in {elapsed:.2f} seconds")
            
            return key
            
        except Exception as e:
            raise EncryptionError(f"Key derivation failed: {str(e)}")
    
    def _process_file_chunks(self, input_file: BinaryIO, 
                           output_file: BinaryIO,
                           process_func: callable,
                           total_size: int) -> None:
        """
        Process a file in chunks for memory efficiency.
        
        Args:
            input_file: Input file handle
            output_file: Output file handle  
            process_func: Function to process each chunk
            total_size: Total file size for progress tracking
        """
        processed = 0
        chunk_num = 0
        
        while True:
            chunk = input_file.read(self.CHUNK_SIZE)
            if not chunk:
                break
                
            chunk_num += 1
            processed_chunk = process_func(chunk)
            output_file.write(processed_chunk)
            
            processed += len(chunk)
            
            # Log progress for large files
            if total_size > 10 * 1024 * 1024:  # 10MB
                progress = (processed / total_size) * 100
                self.logger.debug(f"Processed chunk {chunk_num}, {progress:.1f}% complete")
    
    def _encrypt_chunk_cbc(self, chunk: bytes, encryptor, 
                          is_final: bool = False) -> bytes:
        """Encrypt a single chunk using CBC mode."""
        try:
            if is_final:
                # Apply padding to final chunk
                padder = padding.PKCS7(128).padder()
                padded_chunk = padder.update(chunk) + padder.finalize()
                return encryptor.update(padded_chunk) + encryptor.finalize()
            else:
                # For non-final chunks, ensure they're block-aligned
                if len(chunk) % 16 != 0:
                    # Pad to block boundary (will be handled properly in final chunk)
                    padding_needed = 16 - (len(chunk) % 16)
                    chunk += b'\x00' * padding_needed
                return encryptor.update(chunk)
        except Exception as e:
            raise EncryptionError(f"Chunk encryption failed: {str(e)}")
    
    def _decrypt_chunk_cbc(self, chunk: bytes, decryptor,
                          is_final: bool = False) -> bytes:
        """Decrypt a single chunk using CBC mode."""
        try:
            decrypted_chunk = decryptor.update(chunk)
            
            if is_final:
                decrypted_chunk += decryptor.finalize()
                # Remove padding from final chunk
                unpadder = padding.PKCS7(128).unpadder()
                return unpadder.update(decrypted_chunk) + unpadder.finalize()
            
            return decrypted_chunk
            
        except Exception as e:
            if "padding" in str(e).lower():
                raise handle_invalid_decryption_key()
            raise DecryptionError(f"Chunk decryption failed: {str(e)}")
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256 (CBC or GCM mode).
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data with metadata prepended
            Format for GCM: salt + nonce + tag + ciphertext
            Format for CBC: salt + iv + ciphertext
            
        Raises:
            ValidationError: If data is invalid
            EncryptionError: If encryption fails
        """
        if not isinstance(data, bytes):
            raise ValidationError("Data to encrypt must be bytes")
        
        try:
            # Generate random salt
            salt = os.urandom(self.salt_size)
            
            # Derive key from password and salt
            key = self._derive_key(salt)
            
            if self.use_gcm:
                return self._encrypt_data_gcm(data, salt, key)
            else:
                return self._encrypt_data_cbc(data, salt, key)
                
        except (ValidationError, EncryptionError):
            raise
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
        finally:
            # Clear key from memory
            if 'key' in locals():
                key = b'\x00' * len(key)
                del key
    
    def _encrypt_data_gcm(self, data: bytes, salt: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-GCM mode (authenticated encryption)."""
        try:
            # Generate random nonce
            nonce = os.urandom(self.DEFAULT_NONCE_SIZE)
            
            # Create GCM cipher
            aesgcm = AESGCM(key)
            
            # Encrypt and authenticate
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # GCM returns ciphertext + tag combined
            # Return: salt + nonce + (ciphertext + tag)
            return salt + nonce + ciphertext
            
        except Exception as e:
            raise EncryptionError(f"GCM encryption failed: {str(e)}")
    
    def _encrypt_data_cbc(self, data: bytes, salt: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-CBC mode."""
        try:
            # Generate random IV
            iv = os.urandom(self.DEFAULT_IV_SIZE)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return: salt + iv + ciphertext
            return salt + iv + encrypted_data
            
        except Exception as e:
            raise EncryptionError(f"CBC encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using AES-256 (auto-detects CBC or GCM mode).
        
        Args:
            encrypted_data: Encrypted data with metadata
            
        Returns:
            Decrypted data
            
        Raises:
            ValidationError: If data is invalid
            DecryptionError: If decryption fails
            AuthenticationError: If authentication fails (GCM mode)
        """
        if not isinstance(encrypted_data, bytes):
            raise ValidationError("Encrypted data must be bytes")
        
        # Auto-detect mode based on data size
        if self._is_gcm_encrypted(encrypted_data):
            return self._decrypt_data_gcm(encrypted_data)
        else:
            return self._decrypt_data_cbc(encrypted_data)
    
    def _is_gcm_encrypted(self, encrypted_data: bytes) -> bool:
        """
        Auto-detect if data was encrypted with GCM mode.
        
        This is a heuristic based on the expected data structure.
        GCM: salt(16) + nonce(12) + tag(16) + ciphertext
        CBC: salt(16) + iv(16) + ciphertext
        """
        min_gcm_size = self.salt_size + self.DEFAULT_NONCE_SIZE + self.GCM_TAG_SIZE
        min_cbc_size = self.salt_size + self.DEFAULT_IV_SIZE
        
        if len(encrypted_data) < min_gcm_size:
            return False
            
        # If we're configured for GCM and data is large enough, assume GCM
        return self.use_gcm
    
    def _decrypt_data_gcm(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-GCM mode."""
        min_size = self.salt_size + self.DEFAULT_NONCE_SIZE + self.GCM_TAG_SIZE
        if len(encrypted_data) < min_size:
            raise handle_corrupted_file("encrypted data", 
                                      f"Too short for GCM format: {len(encrypted_data)} bytes")
        
        try:
            # Extract components
            salt = encrypted_data[:self.salt_size]
            nonce = encrypted_data[self.salt_size:self.salt_size + self.DEFAULT_NONCE_SIZE]
            ciphertext_and_tag = encrypted_data[self.salt_size + self.DEFAULT_NONCE_SIZE:]
            
            # Derive key
            key = self._derive_key(salt)
            
            # Create GCM cipher and decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
            
            return plaintext
            
        except Exception as e:
            # Clear key from memory
            if 'key' in locals():
                key = b'\x00' * len(key)
                del key
                
            error_msg = str(e).lower()
            if "invalid" in error_msg or "authentication" in error_msg:
                raise handle_invalid_decryption_key()
            else:
                raise DecryptionError(f"GCM decryption failed: {str(e)}")
    
    def _decrypt_data_cbc(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-CBC mode."""
        min_size = self.salt_size + self.DEFAULT_IV_SIZE
        if len(encrypted_data) < min_size:
            raise handle_corrupted_file("encrypted data",
                                      f"Too short for CBC format: {len(encrypted_data)} bytes")
        
        try:
            # Extract components
            salt = encrypted_data[:self.salt_size]
            iv = encrypted_data[self.salt_size:self.salt_size + self.DEFAULT_IV_SIZE]
            ciphertext = encrypted_data[self.salt_size + self.DEFAULT_IV_SIZE:]
            
            if len(ciphertext) == 0:
                raise handle_corrupted_file("encrypted data", "No ciphertext found")
            
            # Derive key
            key = self._derive_key(salt)
            
            # Create cipher and decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            # Clear key from memory
            if 'key' in locals():
                key = b'\x00' * len(key)
                del key
                
            error_msg = str(e).lower()
            if "padding" in error_msg:
                raise handle_invalid_decryption_key()
            else:
                raise DecryptionError(f"CBC decryption failed: {str(e)}")
    
    def encrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path]) -> None:
        """
        Encrypt a file using AES encryption with chunked processing for large files.
        
        Args:
            input_path: Path to input file
            output_path: Path to output file
            
        Raises:
            FileOperationError: If file operations fail
            EncryptionError: If encryption fails
        """
        start_time = time.time()
        
        # Validate file paths
        input_path = validate_file_access(input_path, "read")
        output_path = Path(output_path)
        
        # Get file size for progress tracking
        file_size = input_path.stat().st_size
        
        # Log operation start
        log_operation_start("encryption", input_path, 
                          f"AES-{'GCM' if self.use_gcm else 'CBC'}", self.logger)
        
        try:
            if file_size <= self.CHUNK_SIZE:
                # Small file: process in memory
                self._encrypt_small_file(input_path, output_path)
            else:
                # Large file: use chunked processing
                self._encrypt_large_file(input_path, output_path, file_size)
                
            # Log completion
            elapsed_time = time.time() - start_time
            log_operation_complete("encryption", output_path, elapsed_time, self.logger)
            
        except Exception as e:
            # Clean up partial output file on failure
            try:
                if output_path.exists():
                    output_path.unlink()
            except:
                pass
            
            if isinstance(e, (FileOperationError, EncryptionError)):
                raise
            raise EncryptionError(f"File encryption failed: {str(e)}")
        finally:
            # Clear password after use (unless in testing mode)
            if not self.testing_mode:
                self._clear_password()
    
    def _encrypt_small_file(self, input_path: Path, output_path: Path) -> None:
        """Encrypt small files by loading entirely into memory."""
        try:
            with open(input_path, 'rb') as infile:
                data = infile.read()
            
            encrypted_data = self.encrypt_data(data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(encrypted_data)
                
        except PermissionError as e:
            raise FileOperationError(f"Permission denied: {str(e)}")
        except OSError as e:
            raise FileOperationError(f"File system error: {str(e)}")
    
    def _encrypt_large_file(self, input_path: Path, output_path: Path, file_size: int) -> None:
        """Encrypt large files using chunked processing."""
        self.logger.info(f"Using chunked processing for large file ({file_size / (1024*1024):.1f} MB)")
        
        try:
            # Generate metadata
            salt = os.urandom(self.salt_size)
            key = self._derive_key(salt)
            
            if self.use_gcm:
                raise EncryptionError("GCM mode not supported for chunked processing of large files")
            
            # Use CBC mode for large files
            iv = os.urandom(self.DEFAULT_IV_SIZE)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write headers
                outfile.write(salt + iv)
                
                # Process file in chunks
                processed = 0
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    is_final = len(chunk) < self.CHUNK_SIZE or (processed + len(chunk)) >= file_size
                    encrypted_chunk = self._encrypt_chunk_cbc(chunk, encryptor, is_final)
                    outfile.write(encrypted_chunk)
                    
                    processed += len(chunk)
                    
                    if file_size > 50 * 1024 * 1024:  # Log progress for files > 50MB
                        progress = (processed / file_size) * 100
                        self.logger.info(f"Encryption progress: {progress:.1f}%")
                    
                    if is_final:
                        break
                        
        except Exception as e:
            if 'key' in locals():
                key = b'\x00' * len(key)
                del key
            raise EncryptionError(f"Large file encryption failed: {str(e)}")
    
    def decrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path]) -> None:
        """
        Decrypt a file using AES decryption with chunked processing for large files.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output file
            
        Raises:
            FileOperationError: If file operations fail
            DecryptionError: If decryption fails
            AuthenticationError: If authentication fails
        """
        start_time = time.time()
        
        # Validate file paths
        input_path = validate_file_access(input_path, "read")
        output_path = Path(output_path)
        
        # Get file size
        file_size = input_path.stat().st_size
        
        if file_size == 0:
            raise handle_corrupted_file(input_path, "File is empty")
        
        # Log operation start
        log_operation_start("decryption", input_path, 
                          f"AES-{'GCM' if self.use_gcm else 'CBC'}", self.logger)
        
        try:
            if file_size <= self.CHUNK_SIZE + 64:  # Small file + metadata overhead
                # Small file: process in memory
                self._decrypt_small_file(input_path, output_path)
            else:
                # Large file: use chunked processing
                self._decrypt_large_file(input_path, output_path, file_size)
                
            # Log completion
            elapsed_time = time.time() - start_time
            log_operation_complete("decryption", output_path, elapsed_time, self.logger)
            
        except Exception as e:
            # Clean up partial output file on failure
            try:
                if output_path.exists():
                    output_path.unlink()
            except:
                pass
                
            if isinstance(e, (FileOperationError, DecryptionError, AuthenticationError)):
                raise
            raise DecryptionError(f"File decryption failed: {str(e)}")
        finally:
            # Clear password after use (unless in testing mode)
            if not self.testing_mode:
                self._clear_password()
    
    def _decrypt_small_file(self, input_path: Path, output_path: Path) -> None:
        """Decrypt small files by loading entirely into memory."""
        try:
            with open(input_path, 'rb') as infile:
                encrypted_data = infile.read()
            
            decrypted_data = self.decrypt_data(encrypted_data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
                
        except PermissionError as e:
            raise FileOperationError(f"Permission denied: {str(e)}")
        except OSError as e:
            raise FileOperationError(f"File system error: {str(e)}")
    
    def _decrypt_large_file(self, input_path: Path, output_path: Path, file_size: int) -> None:
        """Decrypt large files using chunked processing."""
        self.logger.info(f"Using chunked processing for large file ({file_size / (1024*1024):.1f} MB)")
        
        try:
            with open(input_path, 'rb') as infile:
                # Read headers
                salt = infile.read(self.salt_size)
                iv = infile.read(self.DEFAULT_IV_SIZE)
                
                if len(salt) != self.salt_size or len(iv) != self.DEFAULT_IV_SIZE:
                    raise handle_corrupted_file(input_path, "Invalid file headers")
                
                # Derive key and setup decryptor
                key = self._derive_key(salt)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                decryptor = cipher.decryptor()
                
                with open(output_path, 'wb') as outfile:
                    # Process file in chunks
                    processed = self.salt_size + self.DEFAULT_IV_SIZE
                    remaining = file_size - processed
                    
                    while remaining > 0:
                        chunk_size = min(self.CHUNK_SIZE, remaining)
                        chunk = infile.read(chunk_size)
                        
                        if not chunk:
                            break
                            
                        is_final = remaining <= len(chunk)
                        decrypted_chunk = self._decrypt_chunk_cbc(chunk, decryptor, is_final)
                        outfile.write(decrypted_chunk)
                        
                        processed += len(chunk)
                        remaining -= len(chunk)
                        
                        if file_size > 50 * 1024 * 1024:  # Log progress for files > 50MB
                            progress = (processed / file_size) * 100
                            self.logger.info(f"Decryption progress: {progress:.1f}%")
                            
        except Exception as e:
            if 'key' in locals():
                key = b'\x00' * len(key)
                del key
            
            if isinstance(e, (DecryptionError, AuthenticationError)):
                raise
            raise DecryptionError(f"Large file decryption failed: {str(e)}")


def demo_aes() -> None:
    """Demonstrate AES encryption functionality with both modes."""
    print("=== Enhanced AES Encryption Demo ===")
    
    # Test both modes
    for use_gcm in [True, False]:
        mode_name = "GCM" if use_gcm else "CBC"
        print(f"\n--- Testing AES-{mode_name} Mode ---")
        
        # Create AES encryption instance
        password = "demo_password_123!"
        aes = AESEncryption(password, use_gcm=use_gcm)
        
        # Test data encryption
        original_data = b"Hello, World! This is a test message for AES encryption with enhanced security."
        encrypted_data = aes.encrypt_data(original_data)
        decrypted_data = aes.decrypt_data(encrypted_data)
        
        print(f"Original:  {original_data}")
        print(f"Encrypted: {base64.b64encode(encrypted_data).decode()[:50]}...")
        print(f"Decrypted: {decrypted_data}")
        print(f"Match: {original_data == decrypted_data}")
        print(f"Mode: AES-256-{mode_name}")


if __name__ == "__main__":
    demo_aes()


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
