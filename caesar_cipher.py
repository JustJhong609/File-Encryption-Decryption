"""
Caesar Cipher Implementation

This module provides Caesar cipher encryption and decryption functionality.
The Caesar cipher is a simple substitution cipher where each byte is shifted
by a fixed number of positions. For text files, it shifts letters in the alphabet.
For binary files, it performs modular arithmetic on all bytes.
"""

import string
from pathlib import Path
from validation import ValidationError, validate_file_path


class CaesarCipher:
    """
    Caesar cipher implementation for file encryption and decryption.
    
    Supports two modes:
    1. Text mode: Shifts only letters (A-Z, a-z), preserves other characters
    2. Binary mode: Shifts all bytes using modular arithmetic (0-255)
    """
    
    def __init__(self, shift, binary_mode=False):
        """
        Initialize Caesar cipher with a shift value.
        
        Args:
            shift (int): Number of positions to shift (1-25 for text, 1-255 for binary)
            binary_mode (bool): If True, operates on all bytes. If False, only letters.
            
        Raises:
            ValidationError: If shift value is invalid
        """
        from validation import validate_caesar_shift
        
        self.binary_mode = binary_mode
        
        if binary_mode:
            # For binary mode, allow shifts 1-255
            if not isinstance(shift, int) or not (1 <= shift <= 255):
                raise ValidationError(
                    f"Binary mode shift must be between 1 and 255, got {shift}"
                )
        else:
            # For text mode, use standard validation
            shift = validate_caesar_shift(shift)
        
        self.shift = shift
        
        if not binary_mode:
            # Set up translation tables for text mode
            self.alphabet = string.ascii_lowercase
            self.encrypt_table = str.maketrans(
                self.alphabet + self.alphabet.upper(),
                self._shifted_alphabet(shift) + self._shifted_alphabet(shift).upper()
            )
            self.decrypt_table = str.maketrans(
                self._shifted_alphabet(shift) + self._shifted_alphabet(shift).upper(),
                self.alphabet + self.alphabet.upper()
            )
    
    def _shifted_alphabet(self, shift):
        """Create shifted alphabet for encryption."""
        return self.alphabet[shift:] + self.alphabet[:shift]
    
    def encrypt_text(self, text):
        """
        Encrypt text using Caesar cipher (text mode only).
        
        Args:
            text (str): Text to encrypt
            
        Returns:
            str: Encrypted text
            
        Raises:
            ValidationError: If called in binary mode
        """
        if self.binary_mode:
            raise ValidationError("encrypt_text() not available in binary mode. Use encrypt_bytes().")
        
        if not isinstance(text, str):
            raise ValidationError("Input must be a string for text encryption")
        
        return text.translate(self.encrypt_table)
    
    def decrypt_text(self, text):
        """
        Decrypt text using Caesar cipher (text mode only).
        
        Args:
            text (str): Text to decrypt
            
        Returns:
            str: Decrypted text
            
        Raises:
            ValidationError: If called in binary mode
        """
        if self.binary_mode:
            raise ValidationError("decrypt_text() not available in binary mode. Use decrypt_bytes().")
        
        if not isinstance(text, str):
            raise ValidationError("Input must be a string for text decryption")
        
        return text.translate(self.decrypt_table)
    
    def encrypt_bytes(self, data):
        """
        Encrypt bytes using Caesar cipher (shifts all bytes).
        
        Args:
            data (bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        if not isinstance(data, bytes):
            raise ValidationError("Input must be bytes for byte encryption")
        
        return bytes((byte + self.shift) % 256 for byte in data)
    
    def decrypt_bytes(self, data):
        """
        Decrypt bytes using Caesar cipher (shifts all bytes).
        
        Args:
            data (bytes): Data to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if not isinstance(data, bytes):
            raise ValidationError("Input must be bytes for byte decryption")
        
        return bytes((byte - self.shift) % 256 for byte in data)
    
    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file using Caesar cipher.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
            
        Raises:
            ValidationError: If file operations fail
        """
        # Validate file paths
        input_path = validate_file_path(input_path, check_exists=True, check_readable=True)
        output_path = validate_file_path(output_path, check_exists=False, check_writable=True)
        
        try:
            if self.binary_mode:
                # Binary mode: read as bytes and encrypt all bytes
                with open(input_path, 'rb') as infile:
                    content = infile.read()
                
                encrypted_content = self.encrypt_bytes(content)
                
                with open(output_path, 'wb') as outfile:
                    outfile.write(encrypted_content)
            else:
                # Text mode: try to read as text first
                try:
                    with open(input_path, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                    
                    if len(content) == 0:
                        # Empty file - just create empty output
                        with open(output_path, 'w', encoding='utf-8') as outfile:
                            outfile.write("")
                        return
                    
                    encrypted_content = self.encrypt_text(content)
                    
                    with open(output_path, 'w', encoding='utf-8') as outfile:
                        outfile.write(encrypted_content)
                        
                except UnicodeDecodeError:
                    raise ValidationError(
                        f"Cannot decrypt '{input_path}' as text. "
                        "For binary files, use CaesarCipher with binary_mode=True"
                    )
                    
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
        Decrypt a file using Caesar cipher.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
            
        Raises:
            ValidationError: If file operations fail
        """
        # Validate file paths
        input_path = validate_file_path(input_path, check_exists=True, check_readable=True)
        output_path = validate_file_path(output_path, check_exists=False, check_writable=True)
        
        try:
            if self.binary_mode:
                # Binary mode: read as bytes and decrypt all bytes
                with open(input_path, 'rb') as infile:
                    content = infile.read()
                
                if len(content) == 0:
                    raise ValidationError("Input file is empty")
                
                decrypted_content = self.decrypt_bytes(content)
                
                with open(output_path, 'wb') as outfile:
                    outfile.write(decrypted_content)
            else:
                # Text mode: read as text
                with open(input_path, 'r', encoding='utf-8') as infile:
                    content = infile.read()
                
                if len(content) == 0:
                    # Empty file - just create empty output
                    with open(output_path, 'w', encoding='utf-8') as outfile:
                        outfile.write("")
                    return
                
                decrypted_content = self.decrypt_text(content)
                
                with open(output_path, 'w', encoding='utf-8') as outfile:
                    outfile.write(decrypted_content)
                    
        except PermissionError as e:
            raise ValidationError(f"Permission denied: {str(e)}")
        except OSError as e:
            raise ValidationError(f"File system error: {str(e)}")
        except UnicodeDecodeError as e:
            raise ValidationError(f"Text decoding failed: {str(e)}. File may not be text-encrypted.")
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"File decryption failed: {str(e)}")


def demo_caesar():
    """Demonstrate Caesar cipher functionality."""
    print("=== Caesar Cipher Demo ===")
    
    # Create cipher with shift of 3
    cipher = CaesarCipher(3)
    
    # Test text encryption
    original_text = "Hello, World! This is a test message."
    encrypted_text = cipher.encrypt_text(original_text)
    decrypted_text = cipher.decrypt_text(encrypted_text)
    
    print(f"Original:  {original_text}")
    print(f"Encrypted: {encrypted_text}")
    print(f"Decrypted: {decrypted_text}")
    print(f"Match: {original_text == decrypted_text}")


if __name__ == "__main__":
    demo_caesar()
