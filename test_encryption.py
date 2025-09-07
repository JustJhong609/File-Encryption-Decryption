#!/usr/bin/env python3
"""
Test script for file encryption and decryption functionality.

This script creates test files and demonstrates both Caesar cipher
and AES encryption/decryption capabilities.
"""

import os
import tempfile
from pathlib import Path
from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption


def create_test_files():
    """Create test files for encryption/decryption testing."""
    test_dir = Path("test_files")
    test_dir.mkdir(exist_ok=True)
    
    # Create a text file
    text_file = test_dir / "sample.txt"
    with open(text_file, 'w', encoding='utf-8') as f:
        f.write("""This is a sample text file for testing encryption and decryption.
It contains multiple lines and various characters.
Special characters: !@#$%^&*()_+-=[]{}|;:,.<>?
Numbers: 0123456789
Mixed case: AbCdEfGhIjKlMnOpQrStUvWxYz""")
    
    # Create a binary file (simple example)
    binary_file = test_dir / "sample.bin"
    with open(binary_file, 'wb') as f:
        f.write(bytes(range(256)))  # Write all possible byte values
    
    print(f"Created test files:")
    print(f"  - {text_file}")
    print(f"  - {binary_file}")
    
    return text_file, binary_file


def test_caesar_cipher():
    """Test Caesar cipher encryption and decryption."""
    print("\n=== Testing Caesar Cipher ===")
    
    text_file, binary_file = create_test_files()
    
    # Test with different shift values
    for shift in [1, 5, 13, 25]:
        print(f"\nTesting Caesar cipher with shift {shift}:")
        
        cipher = CaesarCipher(shift)
        
        # Test text file
        encrypted_file = text_file.with_suffix('.caesar')
        decrypted_file = text_file.with_suffix('.decrypted.txt')
        
        try:
            # Encrypt
            cipher.encrypt_file(text_file, encrypted_file)
            print(f"  ✓ Encrypted: {encrypted_file}")
            
            # Decrypt
            cipher.decrypt_file(encrypted_file, decrypted_file)
            print(f"  ✓ Decrypted: {decrypted_file}")
            
            # Verify content matches
            with open(text_file, 'r') as f1, open(decrypted_file, 'r') as f2:
                original = f1.read()
                decrypted = f2.read()
                if original == decrypted:
                    print(f"  ✓ Content verification passed")
                else:
                    print(f"  ✗ Content verification failed")
            
            # Clean up
            encrypted_file.unlink(missing_ok=True)
            decrypted_file.unlink(missing_ok=True)
            
        except Exception as e:
            print(f"  ✗ Error: {e}")


def test_aes_encryption():
    """Test AES encryption and decryption."""
    print("\n=== Testing AES Encryption ===")
    
    text_file, binary_file = create_test_files()
    
    # Test with different passwords
    passwords = ["test123", "very_secure_password_456", "短密码"]
    
    for password in passwords:
        print(f"\nTesting AES with password: '{password}'")
        
        aes = AESEncryption(password)
        
        # Test both text and binary files
        for test_file, file_type in [(text_file, "text"), (binary_file, "binary")]:
            encrypted_file = test_file.with_suffix('.enc')
            decrypted_file = test_file.with_suffix('.decrypted' + test_file.suffix)
            
            try:
                # Encrypt
                aes.encrypt_file(test_file, encrypted_file)
                print(f"  ✓ Encrypted {file_type} file: {encrypted_file}")
                
                # Decrypt
                aes.decrypt_file(encrypted_file, decrypted_file)
                print(f"  ✓ Decrypted {file_type} file: {decrypted_file}")
                
                # Verify content matches
                with open(test_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                    original = f1.read()
                    decrypted = f2.read()
                    if original == decrypted:
                        print(f"  ✓ {file_type.capitalize()} content verification passed")
                    else:
                        print(f"  ✗ {file_type.capitalize()} content verification failed")
                
                # Clean up
                encrypted_file.unlink(missing_ok=True)
                decrypted_file.unlink(missing_ok=True)
                
            except Exception as e:
                print(f"  ✗ Error with {file_type} file: {e}")


def test_edge_cases():
    """Test edge cases and error handling."""
    print("\n=== Testing Edge Cases ===")
    
    # Test empty file
    empty_file = Path("test_files/empty.txt")
    empty_file.parent.mkdir(exist_ok=True)
    empty_file.touch()
    
    print("\nTesting empty file:")
    
    # Caesar cipher with empty file
    try:
        cipher = CaesarCipher(5)
        encrypted_file = empty_file.with_suffix('.caesar')
        decrypted_file = empty_file.with_suffix('.decrypted.txt')
        
        cipher.encrypt_file(empty_file, encrypted_file)
        cipher.decrypt_file(encrypted_file, decrypted_file)
        print("  ✓ Caesar cipher handles empty file")
        
        encrypted_file.unlink(missing_ok=True)
        decrypted_file.unlink(missing_ok=True)
        
    except Exception as e:
        print(f"  ✗ Caesar cipher error with empty file: {e}")
    
    # AES with empty file
    try:
        aes = AESEncryption("password")
        encrypted_file = empty_file.with_suffix('.enc')
        decrypted_file = empty_file.with_suffix('.decrypted.txt')
        
        aes.encrypt_file(empty_file, encrypted_file)
        aes.decrypt_file(encrypted_file, decrypted_file)
        print("  ✓ AES handles empty file")
        
        encrypted_file.unlink(missing_ok=True)
        decrypted_file.unlink(missing_ok=True)
        
    except Exception as e:
        print(f"  ✗ AES error with empty file: {e}")
    
    # Test invalid Caesar cipher keys
    print("\nTesting invalid Caesar cipher keys:")
    try:
        CaesarCipher(0)
        print("  ✗ Should have rejected key 0")
    except ValueError:
        print("  ✓ Correctly rejected key 0")
    
    try:
        CaesarCipher(26)
        print("  ✗ Should have rejected key 26")
    except ValueError:
        print("  ✓ Correctly rejected key 26")
    
    # Clean up
    empty_file.unlink(missing_ok=True)


def cleanup_test_files():
    """Clean up test files and directory."""
    import shutil
    test_dir = Path("test_files")
    if test_dir.exists():
        shutil.rmtree(test_dir)
        print(f"\nCleaned up test directory: {test_dir}")


def main():
    """Run all tests."""
    print("File Encryption/Decryption Test Suite")
    print("=" * 50)
    
    try:
        test_caesar_cipher()
        test_aes_encryption()
        test_edge_cases()
        
        print("\n" + "=" * 50)
        print("All tests completed!")
        
    except KeyboardInterrupt:
        print("\nTests interrupted by user.")
    except Exception as e:
        print(f"\nUnexpected error during testing: {e}")
    finally:
        cleanup_test_files()


if __name__ == "__main__":
    main()
