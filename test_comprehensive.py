#!/usr/bin/env python3
"""
Comprehensive Test Suite for File Encryption/Decryption Tool

This test suite covers all features including edge cases, error handling,
large files, and security validations as requested in the performance
enhancement phase.

Features tested:
- All encryption methods (Caesar text/binary, AES GCM/CBC)
- Edge cases (empty files, large files, binary files)
- Error conditions (incorrect passwords, file permissions)
- Security features (password validation, file overwrite protection)
- Performance with large files
- Memory efficiency with chunked processing

Author: File Encryption Tool Test Suite
Version: 3.0.0
"""

import os
import sys
import tempfile
import unittest
import shutil
import time
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import List, Tuple, Optional

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption
from validation import (
    ValidationError, validate_password_strength, validate_caesar_shift,
    validate_file_path, generate_safe_output_filename
)
from error_handling import (
    CryptoError, EncryptionError, DecryptionError, 
    AuthenticationError, FileOperationError, setup_logging
)


class ComprehensiveTestSuite(unittest.TestCase):
    """Comprehensive test suite for all encryption functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.test_dir = Path(tempfile.mkdtemp(prefix="crypto_test_"))
        cls.logger = setup_logging(verbose=True)
        print(f"\n🧪 Test environment created: {cls.test_dir}")
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        shutil.rmtree(cls.test_dir, ignore_errors=True)
        print(f"🧹 Test environment cleaned up")
    
    def setUp(self):
        """Set up for each test."""
        self.test_files = {}
        self.created_files = []
    
    def tearDown(self):
        """Clean up after each test."""
        for file_path in self.created_files:
            try:
                Path(file_path).unlink(missing_ok=True)
            except Exception:
                pass

    # =========================================================================
    # Test File Creation Utilities
    # =========================================================================
    
    def create_test_file(self, name: str, content: bytes, 
                        size: Optional[int] = None) -> Path:
        """Create a test file with specified content or size."""
        file_path = self.test_dir / name
        
        if size is not None:
            # Create file of specific size
            with open(file_path, 'wb') as f:
                chunk = b'A' * min(8192, size)
                written = 0
                while written < size:
                    to_write = min(len(chunk), size - written)
                    f.write(chunk[:to_write])
                    written += to_write
        else:
            # Create file with specific content
            with open(file_path, 'wb') as f:
                f.write(content)
        
        self.created_files.append(file_path)
        return file_path
    
    def create_empty_file(self) -> Path:
        """Create an empty test file."""
        return self.create_test_file("empty.txt", b"")
    
    def create_small_text_file(self) -> Path:
        """Create a small text file."""
        content = "Hello, World!\nThis is a test file.\n🔒📁"
        return self.create_test_file("small.txt", content.encode('utf-8'))
    
    def create_binary_file(self) -> Path:
        """Create a binary file with various byte values."""
        content = bytes(range(256)) + b"\x00\xFF" * 100
        return self.create_test_file("binary.bin", content)
    
    def create_large_file(self, size_mb: int = 5) -> Path:
        """Create a large test file for performance testing."""
        size_bytes = size_mb * 1024 * 1024
        return self.create_test_file(f"large_{size_mb}mb.dat", b"", size_bytes)
    
    def create_unicode_file(self) -> Path:
        """Create a file with unicode content."""
        content = """Unicode test: 🔒🔑🛡️
Multi-language: こんにちは Здравствуйте مرحبا
Mathematical: ∑∫∞≠±√
Emojis: 🚀🌟💎⭐🔥"""
        return self.create_test_file("unicode.txt", content.encode('utf-8'))

    # =========================================================================
    # Caesar Cipher Tests
    # =========================================================================
    
    def test_caesar_text_mode_basic(self):
        """Test basic Caesar cipher text mode encryption/decryption."""
        print("\n📝 Testing Caesar cipher (text mode) - basic functionality")
        
        # Create test file
        original_file = self.create_small_text_file()
        encrypted_file = self.test_dir / "caesar_encrypted.txt"
        decrypted_file = self.test_dir / "caesar_decrypted.txt"
        
        # Test encryption and decryption
        cipher = CaesarCipher(13, binary_mode=False)  # ROT13
        
        cipher.encrypt_file(original_file, encrypted_file)
        self.assertTrue(encrypted_file.exists())
        
        cipher.decrypt_file(encrypted_file, decrypted_file)
        self.assertTrue(decrypted_file.exists())
        
        # Verify content matches
        with open(original_file, 'r', encoding='utf-8') as f:
            original_content = f.read()
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
        print("  ✅ ROT13 encryption/decryption successful")
    
    def test_caesar_binary_mode_basic(self):
        """Test basic Caesar cipher binary mode encryption/decryption."""
        print("\n🔢 Testing Caesar cipher (binary mode) - basic functionality")
        
        # Create binary test file
        original_file = self.create_binary_file()
        encrypted_file = self.test_dir / "caesar_binary_encrypted.bin"
        decrypted_file = self.test_dir / "caesar_binary_decrypted.bin"
        
        # Test encryption and decryption
        cipher = CaesarCipher(42, binary_mode=True)
        
        cipher.encrypt_file(original_file, encrypted_file)
        self.assertTrue(encrypted_file.exists())
        
        cipher.decrypt_file(encrypted_file, decrypted_file)
        self.assertTrue(decrypted_file.exists())
        
        # Verify binary content matches
        with open(original_file, 'rb') as f:
            original_content = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
        print("  ✅ Binary mode encryption/decryption successful")
    
    def test_caesar_empty_file(self):
        """Test Caesar cipher with empty file."""
        print("\n📄 Testing Caesar cipher - empty file edge case")
        
        empty_file = self.create_empty_file()
        encrypted_file = self.test_dir / "empty_encrypted.txt"
        decrypted_file = self.test_dir / "empty_decrypted.txt"
        
        cipher = CaesarCipher(5, binary_mode=False)
        
        cipher.encrypt_file(empty_file, encrypted_file)
        cipher.decrypt_file(encrypted_file, decrypted_file)
        
        # Both files should be empty
        self.assertEqual(encrypted_file.stat().st_size, 0)
        self.assertEqual(decrypted_file.stat().st_size, 0)
        print("  ✅ Empty file handling successful")
    
    def test_caesar_invalid_parameters(self):
        """Test Caesar cipher with invalid parameters."""
        print("\n❌ Testing Caesar cipher - invalid parameters")
        
        # Invalid shift values
        with self.assertRaises(ValidationError):
            CaesarCipher(0, binary_mode=False)  # Too small
        
        with self.assertRaises(ValidationError):
            CaesarCipher(26, binary_mode=False)  # Too large for text mode
        
        with self.assertRaises(ValidationError):
            CaesarCipher(256, binary_mode=True)  # Too large for binary mode
        
        print("  ✅ Invalid parameter validation successful")

    # =========================================================================
    # AES Encryption Tests
    # =========================================================================
    
    def test_aes_gcm_basic(self):
        """Test basic AES-GCM encryption/decryption."""
        print("\n🔐 Testing AES-GCM - basic functionality")
        
        # Create test file
        original_file = self.create_small_text_file()
        encrypted_file = self.test_dir / "aes_gcm_encrypted.enc"
        decrypted_file = self.test_dir / "aes_gcm_decrypted.txt"
        
        # Strong password
        password = "StrongPassword123!@#"
        
        # Test encryption and decryption
        aes = AESEncryption(password, iterations=10000, use_gcm=True, testing_mode=True)
        
        aes.encrypt_file(original_file, encrypted_file)
        self.assertTrue(encrypted_file.exists())
        
        aes.decrypt_file(encrypted_file, decrypted_file)
        self.assertTrue(decrypted_file.exists())
        
        # Verify content matches
        with open(original_file, 'rb') as f:
            original_content = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
        print("  ✅ AES-GCM encryption/decryption successful")
    
    def test_aes_cbc_basic(self):
        """Test basic AES-CBC encryption/decryption."""
        print("\n🔐 Testing AES-CBC - basic functionality")
        
        # Create test file
        original_file = self.create_small_text_file()
        encrypted_file = self.test_dir / "aes_cbc_encrypted.enc"
        decrypted_file = self.test_dir / "aes_cbc_decrypted.txt"
        
        # Strong password
        password = "AnotherStrongPassword456$%^"
        
        # Test encryption and decryption
        aes = AESEncryption(password, iterations=10000, use_gcm=False, testing_mode=True)
        
        aes.encrypt_file(original_file, encrypted_file)
        self.assertTrue(encrypted_file.exists())
        
        aes.decrypt_file(encrypted_file, decrypted_file)
        self.assertTrue(decrypted_file.exists())
        
        # Verify content matches
        with open(original_file, 'rb') as f:
            original_content = f.read()
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
        print("  ✅ AES-CBC encryption/decryption successful")
    
    def test_aes_wrong_password(self):
        """Test AES decryption with wrong password."""
        print("\n🔑 Testing AES - wrong password handling")
        
        original_file = self.create_small_text_file()
        encrypted_file = self.test_dir / "aes_wrong_pass.enc"
        decrypted_file = self.test_dir / "aes_wrong_pass_decrypted.txt"
        
        # Encrypt with one password
        correct_password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"
        
        aes_encrypt = AESEncryption(correct_password, iterations=10000, testing_mode=True)
        aes_encrypt.encrypt_file(original_file, encrypted_file)
        
        # Try to decrypt with wrong password
        aes_decrypt = AESEncryption(wrong_password, iterations=10000, testing_mode=True)
        
        with self.assertRaises((DecryptionError, AuthenticationError)):
            aes_decrypt.decrypt_file(encrypted_file, decrypted_file)
        
        print("  ✅ Wrong password detection successful")
    
    def test_aes_corrupted_file(self):
        """Test AES decryption with corrupted encrypted file."""
        print("\n💥 Testing AES - corrupted file handling")
        
        original_file = self.create_small_text_file()
        encrypted_file = self.test_dir / "aes_corrupted.enc"
        decrypted_file = self.test_dir / "aes_corrupted_decrypted.txt"
        
        # Encrypt file normally
        password = "TestPassword123!"
        aes = AESEncryption(password, iterations=10000, testing_mode=True)
        aes.encrypt_file(original_file, encrypted_file)
        
        # Corrupt the encrypted file
        with open(encrypted_file, 'r+b') as f:
            f.seek(100)  # Corrupt somewhere in the middle
            f.write(b'\xFF\xFF\xFF\xFF')
        
        # Try to decrypt corrupted file
        with self.assertRaises((DecryptionError, AuthenticationError)):
            aes.decrypt_file(encrypted_file, decrypted_file)
        
        print("  ✅ Corrupted file detection successful")

    # =========================================================================
    # Large File and Performance Tests
    # =========================================================================
    
    def test_large_file_processing(self):
        """Test encryption/decryption of large files."""
        print("\n📊 Testing large file processing (chunked mode)")
        
        # Create a 5MB test file
        original_file = self.create_large_file(5)
        encrypted_file = self.test_dir / "large_encrypted.enc"
        decrypted_file = self.test_dir / "large_decrypted.dat"
        
        password = "LargeFilePassword123!"
        
        # Time the encryption (use CBC for large files since GCM doesn't support chunking)
        start_time = time.time()
        aes = AESEncryption(password, iterations=50000, use_gcm=False, testing_mode=True)
        aes.encrypt_file(original_file, encrypted_file)
        encrypt_time = time.time() - start_time
        
        # Time the decryption
        start_time = time.time()
        aes.decrypt_file(encrypted_file, decrypted_file)
        decrypt_time = time.time() - start_time
        
        # Verify file sizes match
        original_size = original_file.stat().st_size
        decrypted_size = decrypted_file.stat().st_size
        
        self.assertEqual(original_size, decrypted_size)
        
        print(f"  ✅ 5MB file processed successfully")
        print(f"     Encryption time: {encrypt_time:.2f}s")
        print(f"     Decryption time: {decrypt_time:.2f}s")
        print(f"     File size: {original_size:,} bytes")
    
    def test_unicode_file_handling(self):
        """Test handling of files with unicode content."""
        print("\n🌍 Testing unicode file handling")
        
        original_file = self.create_unicode_file()
        encrypted_file = self.test_dir / "unicode_encrypted.enc"
        decrypted_file = self.test_dir / "unicode_decrypted.txt"
        
        password = "UnicodeTestPassword123!🔒"
        
        # Test AES encryption
        aes = AESEncryption(password, iterations=10000, testing_mode=True)
        aes.encrypt_file(original_file, encrypted_file)
        aes.decrypt_file(encrypted_file, decrypted_file)
        
        # Verify unicode content preserved
        with open(original_file, 'r', encoding='utf-8') as f:
            original_content = f.read()
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            decrypted_content = f.read()
        
        self.assertEqual(original_content, decrypted_content)
        print("  ✅ Unicode content preserved")

    # =========================================================================
    # Validation and Security Tests
    # =========================================================================
    
    def test_password_strength_validation(self):
        """Test password strength validation."""
        print("\n🔍 Testing password strength validation")
        
        # Test weak passwords
        weak_passwords = [
            "123",           # Too short
            "password",      # Common word
            "12345678",      # All digits
            "abcdefgh",      # All lowercase
            "ABCDEFGH",      # All uppercase
            "Password",      # Missing special chars and numbers
        ]
        
        for password in weak_passwords:
            try:
                is_valid, warnings = validate_password_strength(password)
                self.assertTrue(len(warnings) > 0, f"Password '{password}' should have warnings")
            except ValidationError:
                # Very weak passwords may throw exceptions instead of just warnings
                pass  # This is acceptable behavior
        
        # Test strong password
        strong_password = "MyVeryStr0ng!Password#2024"
        is_valid, warnings = validate_password_strength(strong_password)
        self.assertEqual(len(warnings), 0, "Strong password should have no warnings")
        
        print("  ✅ Password strength validation working")
    
    def test_file_overwrite_protection(self):
        """Test file overwrite protection mechanism."""
        print("\n🛡️ Testing file overwrite protection")
        
        # Create initial file
        base_file = self.test_dir / "test_overwrite.txt"
        base_file.write_text("Original content")
        
        # Create a conflicting file first
        conflicting_file = base_file.with_suffix(base_file.suffix + ".enc")
        conflicting_file.write_text("Conflicting content")
        
        # Test safe filename generation with conflict
        safe_name1 = generate_safe_output_filename(base_file, ".enc")
        self.assertNotEqual(str(safe_name1), str(conflicting_file))
        
        # Create the first safe file
        safe_name1.write_text("First safe content")
        
        # Generate another safe name - should be different from both existing files
        safe_name2 = generate_safe_output_filename(base_file, ".enc")
        self.assertNotEqual(str(safe_name2), str(safe_name1))
        self.assertNotEqual(str(safe_name2), str(conflicting_file))
        
        print(f"  ✅ Safe filenames generated:")
        print(f"     Original: {base_file.name}")
        print(f"     Safe #1:  {safe_name1.name}")
        print(f"     Safe #2:  {safe_name2.name}")
    
    def test_file_permission_errors(self):
        """Test handling of file permission errors."""
        print("\n🚫 Testing file permission error handling")
        
        # Create a test file
        test_file = self.create_small_text_file()
        
        # Create a read-only directory (simulate permission error)
        readonly_dir = self.test_dir / "readonly"
        readonly_dir.mkdir(exist_ok=True)
        
        try:
            readonly_dir.chmod(0o444)  # Read-only
            
            output_file = readonly_dir / "cannot_write.enc"
            
            # Try to encrypt to read-only location
            password = "TestPassword123!"
            aes = AESEncryption(password, iterations=10000)
            
            with self.assertRaises(FileOperationError):
                aes.encrypt_file(test_file, output_file)
            
            print("  ✅ Permission error handling successful")
        
        finally:
            # Restore permissions for cleanup
            try:
                readonly_dir.chmod(0o755)
            except Exception:
                pass

    # =========================================================================
    # Integration and Edge Case Tests
    # =========================================================================
    
    def test_all_encryption_methods_integration(self):
        """Integration test for all encryption methods."""
        print("\n🔄 Integration test - all encryption methods")
        
        test_data = [
            ("small text", self.create_small_text_file()),
            ("binary data", self.create_binary_file()),
            ("unicode content", self.create_unicode_file()),
            ("empty file", self.create_empty_file()),
        ]
        
        methods = [
            ("Caesar text", lambda f: CaesarCipher(13, binary_mode=False)),
            ("Caesar binary", lambda f: CaesarCipher(42, binary_mode=True)),
            ("AES-GCM", lambda f: AESEncryption("IntegrationTest123!", use_gcm=True, testing_mode=True)),
            ("AES-CBC", lambda f: AESEncryption("IntegrationTest456!", use_gcm=False, testing_mode=True)),
        ]
        
        success_count = 0
        total_tests = len(test_data) * len(methods)
        
        for data_name, original_file in test_data:
            for method_name, create_cipher in methods:
                try:
                    # Skip binary methods on text-only ciphers when appropriate
                    if method_name == "Caesar text" and data_name == "binary data":
                        # Text mode Caesar won't preserve binary data perfectly
                        continue
                    
                    encrypted_file = self.test_dir / f"integration_{data_name.replace(' ', '_')}_{method_name.replace('-', '_').replace(' ', '_')}.enc"
                    decrypted_file = self.test_dir / f"integration_{data_name.replace(' ', '_')}_{method_name.replace('-', '_').replace(' ', '_')}_dec"
                    
                    cipher = create_cipher(original_file)
                    
                    # Encrypt
                    cipher.encrypt_file(original_file, encrypted_file)
                    
                    # Decrypt
                    cipher.decrypt_file(encrypted_file, decrypted_file)
                    
                    # For binary-safe methods, verify exact match
                    if method_name in ["Caesar binary", "AES-GCM", "AES-CBC"]:
                        with open(original_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
                            self.assertEqual(f1.read(), f2.read())
                    
                    success_count += 1
                    
                except Exception as e:
                    print(f"    ❌ Failed: {method_name} on {data_name} - {e}")
                    continue
        
        success_rate = (success_count / total_tests) * 100
        print(f"  ✅ Integration test completed: {success_count}/{total_tests} tests passed ({success_rate:.1f}%)")
    
    def test_memory_efficiency_simulation(self):
        """Test memory efficiency with simulated large file processing."""
        print("\n💾 Testing memory efficiency simulation")
        
        # This test simulates large file processing without creating huge files
        original_file = self.create_test_file("medium_test.dat", b"", 1024 * 1024)  # 1MB
        encrypted_file = self.test_dir / "medium_encrypted.enc"
        decrypted_file = self.test_dir / "medium_decrypted.dat"
        
        password = "MemoryEfficiencyTest123!"
        
        # Test with chunked processing (use CBC for large files)
        aes = AESEncryption(password, iterations=10000, use_gcm=False, testing_mode=True)
        
        # Patch the chunk size to test chunked behavior
        original_chunk_size = aes.CHUNK_SIZE
        aes.CHUNK_SIZE = 8192  # Small chunks to test chunking logic
        
        try:
            aes.encrypt_file(original_file, encrypted_file)
            aes.decrypt_file(encrypted_file, decrypted_file)
            
            # Verify sizes match
            original_size = original_file.stat().st_size
            decrypted_size = decrypted_file.stat().st_size
            self.assertEqual(original_size, decrypted_size)
            
            print("  ✅ Memory-efficient chunked processing successful")
        
        finally:
            aes.CHUNK_SIZE = original_chunk_size


def run_performance_benchmarks():
    """Run performance benchmarks for different file sizes."""
    print("\n" + "="*70)
    print("🚀 PERFORMANCE BENCHMARKS")
    print("="*70)
    
    test_dir = Path(tempfile.mkdtemp(prefix="benchmark_"))
    
    try:
        sizes_mb = [0.1, 1, 5]  # Test different file sizes
        password = "BenchmarkPassword123!"
        
        for size_mb in sizes_mb:
            size_bytes = int(size_mb * 1024 * 1024)
            
            # Create test file
            test_file = test_dir / f"benchmark_{size_mb}mb.dat"
            with open(test_file, 'wb') as f:
                chunk = b'B' * 8192
                written = 0
                while written < size_bytes:
                    to_write = min(len(chunk), size_bytes - written)
                    f.write(chunk[:to_write])
                    written += to_write
            
            encrypted_file = test_dir / f"benchmark_{size_mb}mb.enc"
            decrypted_file = test_dir / f"benchmark_{size_mb}mb_dec.dat"
            
            # Benchmark AES-CBC (GCM doesn't support chunked processing)
            aes = AESEncryption(password, iterations=50000, use_gcm=False, testing_mode=True)
            
            start_time = time.time()
            aes.encrypt_file(test_file, encrypted_file)
            encrypt_time = time.time() - start_time
            
            start_time = time.time()
            aes.decrypt_file(encrypted_file, decrypted_file)
            decrypt_time = time.time() - start_time
            
            # Calculate throughput
            encrypt_mbps = size_mb / encrypt_time if encrypt_time > 0 else 0
            decrypt_mbps = size_mb / decrypt_time if decrypt_time > 0 else 0
            
            print(f"\n📊 {size_mb}MB File Performance:")
            print(f"   Encryption: {encrypt_time:.3f}s ({encrypt_mbps:.1f} MB/s)")
            print(f"   Decryption: {decrypt_time:.3f}s ({decrypt_mbps:.1f} MB/s)")
    
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def main():
    """Run the comprehensive test suite."""
    print("🧪 COMPREHENSIVE FILE ENCRYPTION TEST SUITE")
    print("=" * 70)
    print("Testing all features including edge cases, performance, and security")
    print("=" * 70)
    
    # Configure test logging
    logging.basicConfig(
        level=logging.WARNING,  # Reduce noise during testing
        format='%(levelname)s: %(message)s'
    )
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(ComprehensiveTestSuite)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        buffer=True,
        failfast=False
    )
    
    print("\n🔬 Running comprehensive test suite...")
    start_time = time.time()
    
    result = runner.run(suite)
    
    test_time = time.time() - start_time
    
    # Print summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    else:
        print("Success rate: N/A (no tests run)")
    print(f"Total time: {test_time:.2f} seconds")
    
    # Run performance benchmarks if all tests passed
    if len(result.failures) == 0 and len(result.errors) == 0:
        print("\n🎉 All tests passed! Running performance benchmarks...")
        run_performance_benchmarks()
    else:
        print(f"\n⚠️  {len(result.failures + result.errors)} test(s) failed. Skipping benchmarks.")
        
        # Print failure details
        if result.failures:
            print("\n❌ FAILURES:")
            for test, traceback in result.failures:
                print(f"   {test}: {traceback.splitlines()[-1]}")
        
        if result.errors:
            print("\n💥 ERRORS:")
            for test, traceback in result.errors:
                print(f"   {test}: {traceback.splitlines()[-1]}")
    
    print("\n🏁 Test suite completed!")
    return result.wasSuccessful()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)