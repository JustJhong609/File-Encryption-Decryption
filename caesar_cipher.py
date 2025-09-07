"""
Caesar Cipher Implementation

This module provides Caesar cipher encryption and decryption functionality.
The Caesar cipher is a simple substitution cipher where each letter is shifted
by a fixed number of positions in the alphabet.
"""

import string
from pathlib import Path


class CaesarCipher:
    """Caesar cipher implementation for file encryption and decryption."""
    
    def __init__(self, shift):
        """
        Initialize Caesar cipher with a shift value.
        
        Args:
            shift (int): Number of positions to shift (1-25)
        """
        if not isinstance(shift, int) or not (1 <= shift <= 25):
            raise ValueError("Shift must be an integer between 1 and 25")
        
        self.shift = shift
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
        Encrypt text using Caesar cipher.
        
        Args:
            text (str): Text to encrypt
            
        Returns:
            str: Encrypted text
        """
        return text.translate(self.encrypt_table)
    
    def decrypt_text(self, text):
        """
        Decrypt text using Caesar cipher.
        
        Args:
            text (str): Text to decrypt
            
        Returns:
            str: Decrypted text
        """
        return text.translate(self.decrypt_table)
    
    def encrypt_file(self, input_path, output_path):
        """
        Encrypt a file using Caesar cipher.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
        """
        try:
            with open(input_path, 'r', encoding='utf-8') as infile:
                content = infile.read()
            
            encrypted_content = self.encrypt_text(content)
            
            with open(output_path, 'w', encoding='utf-8') as outfile:
                outfile.write(encrypted_content)
                
        except UnicodeDecodeError:
            # Handle binary files by reading as bytes
            with open(input_path, 'rb') as infile:
                content = infile.read()
            
            # Convert bytes to text representation for Caesar cipher
            text_content = ''.join(chr(byte) for byte in content)
            encrypted_content = self.encrypt_text(text_content)
            
            with open(output_path, 'w', encoding='utf-8') as outfile:
                outfile.write(encrypted_content)
    
    def decrypt_file(self, input_path, output_path):
        """
        Decrypt a file using Caesar cipher.
        
        Args:
            input_path (Path): Path to input file
            output_path (Path): Path to output file
        """
        with open(input_path, 'r', encoding='utf-8') as infile:
            content = infile.read()
        
        decrypted_content = self.decrypt_text(content)
        
        # Try to determine if original was binary
        try:
            # Check if decrypted content represents binary data
            if all(ord(char) <= 255 for char in decrypted_content):
                # Convert back to bytes if it was originally binary
                binary_data = bytes(ord(char) for char in decrypted_content)
                with open(output_path, 'wb') as outfile:
                    outfile.write(binary_data)
            else:
                raise ValueError("Not binary data")
        except (ValueError, OverflowError):
            # Save as text file
            with open(output_path, 'w', encoding='utf-8') as outfile:
                outfile.write(decrypted_content)


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
