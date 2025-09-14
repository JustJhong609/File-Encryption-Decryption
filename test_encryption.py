#!/usr/bin/env python3
"""
Enhanced test script for file encryption and decryption functionality.

This script creates test files and demonstrates both Caesar cipher
(text and binary modes) and AES encryption/decryption capabilities
with comprehensive error handling and validation testing.
"""

import os
import tempfile
from pathlib import Path
from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption
from validation import ValidationError, validate_password_strength, validate_caesar_shift


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
    """Test Caesar cipher encryption and decryption (text mode)."""
    print("\n=== Testing Caesar Cipher (Text Mode) ===")
    
    text_file, binary_file = create_test_files()
    
    # Test with different shift values
    for shift in [1, 5, 13, 25]:
        print(f"\nTesting Caesar cipher (text mode) with shift {shift}:")
        
        cipher = CaesarCipher(shift, binary_mode=False)
        
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


def test_caesar_cipher_binary():
    """Test Caesar cipher encryption and decryption (binary mode)."""
    print("\n=== Testing Caesar Cipher (Binary Mode) ===")
    
    text_file, binary_file = create_test_files()
    
    # Test with different shift values for binary mode
    for shift in [1, 42, 128, 255]:
        print(f"\nTesting Caesar cipher (binary mode) with shift {shift}:")
        
        cipher = CaesarCipher(shift, binary_mode=True)
        
        # Test both text and binary files
        for test_file, file_type in [(text_file, "text"), (binary_file, "binary")]:
            encrypted_file = test_file.with_suffix('.caesar_bin')
            decrypted_file = test_file.with_suffix('.decrypted_bin' + test_file.suffix)
            
            try:
                # Encrypt
                cipher.encrypt_file(test_file, encrypted_file)
                print(f"  ✓ Encrypted {file_type} file: {encrypted_file}")
                
                # Decrypt
                cipher.decrypt_file(encrypted_file, decrypted_file)
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


def test_aes_encryption():
    """Test AES encryption and decryption."""
    print("\n=== Testing AES Encryption ===")
    
    text_file, binary_file = create_test_files()
    
    # Test with different passwords and configurations
    test_configs = [
        ("strongpassword123", 10000),
        ("very_secure_password_456!", 50000),
        ("简单密码test", 100000),
    ]
    
    for password, iterations in test_configs:
        print(f"\nTesting AES with password: '{password}' ({iterations} iterations)")
        
        try:
            aes = AESEncryption(password, iterations=iterations)
            
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
        except Exception as e:
            print(f"  ✗ AES setup error: {e}")


def test_validation():
    """Test input validation and error handling."""
    print("\n=== Testing Input Validation ===")
    
    # Test Caesar cipher validation
    print("\nTesting Caesar cipher validation:")
    
    # Valid keys
    for shift in [1, 13, 25]:
        try:
            validate_caesar_shift(shift)
            print(f"  ✓ Valid shift {shift} accepted")
        except ValidationError:
            print(f"  ✗ Valid shift {shift} rejected")
    
    # Invalid keys
    for shift in [0, 26, -1, 30]:
        try:
            validate_caesar_shift(shift)
            print(f"  ✗ Invalid shift {shift} should be rejected")
        except ValidationError:
            print(f"  ✓ Invalid shift {shift} correctly rejected")
    
    # Test password strength validation
    print("\nTesting password strength validation:")
    
    test_passwords = [
        ("weak", False),  # Too short
        ("password", True),  # Common password (should warn)
        ("strongpassword123", True),  # Good password
        ("VeryStr0ng!Password#123", True),  # Excellent password
    ]
    
    for password, should_pass in test_passwords:
        try:
            is_valid, warnings = validate_password_strength(password)
            if should_pass:
                print(f"  ✓ Password '{password}' validation passed ({len(warnings)} warnings)")
            else:
                print(f"  ✗ Password '{password}' should have failed")
        except ValidationError:
            if not should_pass:
                print(f"  ✓ Password '{password}' correctly rejected")
            else:
                print(f"  ✗ Password '{password}' should have passed")


def test_edge_cases():
    """Test edge cases and error handling."""
    print("\n=== Testing Edge Cases ===")
    
    # Test empty file
    empty_file = Path("test_files/empty.txt")
    empty_file.parent.mkdir(exist_ok=True)
    empty_file.touch()
    
    print("\nTesting empty file:")
    
    # Caesar cipher with empty file (text mode)
    try:
        cipher = CaesarCipher(5, binary_mode=False)
        encrypted_file = empty_file.with_suffix('.caesar')
        decrypted_file = empty_file.with_suffix('.decrypted.txt')
        
        cipher.encrypt_file(empty_file, encrypted_file)
        cipher.decrypt_file(encrypted_file, decrypted_file)
        print("  ✓ Caesar cipher (text mode) handles empty file")
        
        encrypted_file.unlink(missing_ok=True)
        decrypted_file.unlink(missing_ok=True)
        
    except Exception as e:
        print(f"  ✗ Caesar cipher (text mode) error with empty file: {e}")
    
    # Caesar cipher with empty file (binary mode)
    try:
        cipher = CaesarCipher(42, binary_mode=True)
        encrypted_file = empty_file.with_suffix('.caesar_bin')
        decrypted_file = empty_file.with_suffix('.decrypted_bin.txt')
        
        cipher.encrypt_file(empty_file, encrypted_file)
        cipher.decrypt_file(encrypted_file, decrypted_file)
        print("  ✗ Caesar cipher (binary mode) should reject empty file")
        
    except ValidationError:
        print("  ✓ Caesar cipher (binary mode) correctly rejects empty file")
    except Exception as e:
        print(f"  ? Caesar cipher (binary mode) unexpected error: {e}")
    
    # AES with empty file
    try:
        aes = AESEncryption("testpassword123")
        encrypted_file = empty_file.with_suffix('.enc')
        decrypted_file = empty_file.with_suffix('.decrypted.txt')
        
        aes.encrypt_file(empty_file, encrypted_file)
        aes.decrypt_file(encrypted_file, decrypted_file)
        print("  ✓ AES handles empty file")
        
        encrypted_file.unlink(missing_ok=True)
        decrypted_file.unlink(missing_ok=True)
        
    except Exception as e:
        print(f"  ✗ AES error with empty file: {e}")
    
    # Test invalid Caesar cipher initialization
    print("\nTesting invalid Caesar cipher initialization:")
    
    # Text mode invalid keys
    for shift in [0, 26, -1]:
        try:
            CaesarCipher(shift, binary_mode=False)
            print(f"  ✗ Should have rejected text mode key {shift}")
        except ValidationError:
            print(f"  ✓ Correctly rejected text mode key {shift}")
    
    # Binary mode invalid keys
    for shift in [0, 256, -1]:
        try:
            CaesarCipher(shift, binary_mode=True)
            print(f"  ✗ Should have rejected binary mode key {shift}")
        except ValidationError:
            print(f"  ✓ Correctly rejected binary mode key {shift}")
    
    # Test AES with invalid parameters
    print("\nTesting invalid AES parameters:")
    
    try:
        AESEncryption("", iterations=100000)  # Empty password
        print("  ✗ Should have rejected empty password")
    except ValidationError:
        print("  ✓ Correctly rejected empty password")
    
    try:
        AESEncryption("validpassword", iterations=100)  # Too few iterations
        print("  ✗ Should have rejected low iterations")
    except ValidationError:
        print("  ✓ Correctly rejected low iterations")
    
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
    print("Enhanced File Encryption/Decryption Test Suite")
    print("=" * 60)
    
    try:
        test_caesar_cipher()
        test_caesar_cipher_binary()
        test_aes_encryption()
        test_validation()
        test_edge_cases()
        
        print("\n" + "=" * 60)
        print("All tests completed!")
        
    except KeyboardInterrupt:
        print("\nTests interrupted by user.")
    except Exception as e:
        print(f"\nUnexpected error during testing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup_test_files()


if __name__ == "__main__":
    main()
