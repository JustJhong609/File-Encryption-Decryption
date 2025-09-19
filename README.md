# File Encryption and Decryption Tool v3.0.0

🔒 **Enterprise-grade file encryption/decryption utility** with comprehensive security features, performance optimizations, and production-ready error handling. Supports both educational Caesar cipher and industry-standard AES-256 encryption with authenticated encryption modes.

**NEW in v3.0**: Chunked processing for large files (300+ MB/s), AES-GCM authenticated encryption, comprehensive error handling, verbose logging, and professional CLI with extensive help system.

## 🚀 Performance & Features

### 🏆 Performance Achievements
- **High Throughput**: Up to 310 MB/s decryption speed for large files
- **Memory Efficient**: Chunked processing (64KB chunks) for files of any size
- **Scalable Architecture**: Handles files from empty to multi-GB without memory issues
- **Optimized Algorithms**: AES-GCM mode for better performance than CBC

### 🔒 Encryption Methods

#### AES-256 Encryption (Production Ready)
- **AES-GCM Mode**: Authenticated encryption with integrity protection (recommended)
- **AES-CBC Mode**: Traditional mode for compatibility with older systems
- **Chunked Processing**: Memory-efficient handling of large files (>64KB)
- **Configurable Security**: Adjustable PBKDF2 iterations (default: 100,000)
- **Memory Protection**: Secure password handling with best-effort clearing

#### Caesar Cipher (Educational Only)
- **Text Mode**: Shifts letters only (A-Z, a-z), preserves other characters (shift: 1-25)  
- **Binary Mode**: Shifts all bytes using modular arithmetic (shift: 1-255)
- **Educational Focus**: Includes prominent security warnings about cryptographic weakness

### 🛡️ Security Enhancements
- **Authenticated Encryption**: AES-GCM provides both confidentiality and integrity
- **Password Strength Validation**: Comprehensive validation with detailed security recommendations
- **Secure Key Derivation**: PBKDF2 with configurable iterations and random salts
- **Memory Security**: Best-effort password clearing from memory after operations
- **Input Validation**: Comprehensive validation of all parameters and file paths

### 🔧 Error Handling & Robustness
- **Custom Exception Hierarchy**: Specialized error types (CryptoError, EncryptionError, etc.)
- **User-Friendly Messages**: Clear, actionable error messages with specific guidance
- **Comprehensive Logging**: Configurable logging with file output and debug levels
- **Graceful Recovery**: Safe handling of all error conditions and edge cases
- **File Permission Validation**: Pre-checks for read/write access before operations

### 🎯 Advanced CLI Features
- **Verbose Mode**: Detailed operation logging and progress tracking
- **Professional Help**: Organized argument groups with examples and security guidance
- **Version Information**: Professional version display with build information
- **Smart Filename Generation**: Automatic safe output filenames with conflict resolution
- **Security Warnings**: Prominent warnings for educational vs. production encryption methods

## 📊 Performance Benchmarks

Our comprehensive testing shows excellent performance across different file sizes:

| File Size | Encryption Speed | Decryption Speed | Memory Usage |
|-----------|------------------|------------------|--------------|
| 0.1 MB    | 9.4 MB/s         | 12.0 MB/s        | Low          |
| 1 MB      | 93.4 MB/s        | 110.5 MB/s       | Low          |
| 5 MB+     | 232 MB/s         | 310 MB/s         | Constant     |

*Benchmarks performed on standard hardware with AES-CBC mode and chunked processing.*

## 📋 Requirements

- **Python 3.8+** (recommended for optimal performance)
- **cryptography library** (latest version for security updates)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/JustJhong609/File-Encryption-Decryption.git
cd File-Encryption-Decryption
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🔧 Usage

### 📱 Command Line Interface

The main script `file_crypto.py` provides a comprehensive command-line interface with professional features.

#### 🚀 Quick Start

```bash
# 🔒 Secure AES-GCM encryption (recommended for production)
python file_crypto.py -a encrypt document.pdf
# Password will be prompted securely

# 🔓 AES decryption with auto-detected output filename
python file_crypto.py -a decrypt document.pdf.enc

# 📚 Caesar cipher for educational purposes (with security warning)
python file_crypto.py -a encrypt -m caesar -k 13 message.txt

# 📖 View comprehensive help with examples
python file_crypto.py --help

# ℹ️ Check version information
python file_crypto.py --version
```

#### 🔍 Advanced Usage

```bash
# 🎯 Verbose mode with detailed logging
python file_crypto.py -v -a encrypt large_dataset.csv

# 🔧 Custom security parameters
python file_crypto.py -a encrypt --aes-iterations 200000 --log-file crypto.log sensitive_data.xlsx

# 🏭 Production encryption with specific output
python file_crypto.py -a encrypt -o /secure/encrypted_backup.enc important_files.tar.gz

# ⚡ High-performance mode for large files (uses CBC for chunking)
python file_crypto.py -v -a encrypt --aes-cbc large_video.mp4
```

#### 📋 Command Line Arguments

**Required Arguments:**
- `file`: Input file path to encrypt or decrypt
- `-a, --action`: Action to perform (`encrypt` or `decrypt`)

**Encryption Method Selection:**
- `-m, --method`: Encryption method (`caesar` or `aes`) (default: `aes`)

**File Output Options:**
- `-o, --output`: Custom output file path (optional, auto-generated with safe naming if not specified)
- `--no-overwrite-check`: Disable safe filename generation (⚠️ may overwrite existing files)

**Caesar Cipher Options (Educational Only):**
- `-k, --key`: Caesar shift value (1-25 for text mode, 1-255 for binary mode)
- `--binary-caesar`: Enable binary mode (operates on all bytes, not just letters)

**AES Encryption Options (Production Ready):**
- `--password`: AES password (⚠️ less secure via CLI, will prompt securely if omitted)
- `--aes-iterations`: PBKDF2 iterations for key derivation (default: 100,000, min: 10,000)
- `--aes-cbc`: Use AES-CBC mode instead of GCM (for compatibility or large file chunking)

**Security Options:**
- `--weak-password-ok`: Skip password strength validation warnings

**Logging and Debug Options:**
- `-v, --verbose`: Enable verbose output with detailed progress information
- `--log-file`: Write detailed logs to specified file (useful for debugging)
- `--version`: Show version information and exit

#### 💡 Comprehensive Examples

**🏭 Production Use Cases:**
```bash
# Enterprise-grade document encryption with maximum security
python file_crypto.py -v -a encrypt --aes-iterations 200000 --log-file audit.log confidential_report.docx

# Batch processing with verbose logging and custom output directory
python file_crypto.py -v -a encrypt -o /encrypted_backup/data.enc large_database.sql

# High-performance encryption for large files (automatic chunked processing)
python file_crypto.py -v -a encrypt --aes-cbc multi_gigabyte_file.zip

# Secure decryption with comprehensive logging
python file_crypto.py -v -a decrypt --log-file decrypt_audit.log encrypted_archive.enc
```

**📚 Educational Examples:**
```bash
# ROT13 cipher demonstration (classic educational example)
python file_crypto.py -a encrypt -m caesar -k 13 homework.txt

# Binary Caesar cipher for understanding byte-level operations
python file_crypto.py -a encrypt -m caesar --binary-caesar -k 42 sample_image.png

# Compare encryption methods (Caesar vs AES)
python file_crypto.py -a encrypt -m caesar -k 5 test_file.txt
python file_crypto.py -a encrypt -m aes test_file.txt
```

**🔧 System Administration Examples:**
```bash
# Automated backup encryption with logging
python file_crypto.py -a encrypt --weak-password-ok --password "$BACKUP_PASSWORD" --log-file /var/log/backup.log /data/backup.tar.gz

# Bulk decryption with error handling
python file_crypto.py -v -a decrypt encrypted_config.enc 2>&1 | tee decryption.log

# Performance testing with benchmarking
time python file_crypto.py -v -a encrypt --aes-iterations 50000 large_test_file.bin
```

**⚠️ Security-Conscious Examples:**
```bash
# Maximum security encryption (never provide password via CLI)
python file_crypto.py -a encrypt --aes-iterations 500000 top_secret.pdf

# Verify file integrity after encryption/decryption cycle
python file_crypto.py -a encrypt original.dat
python file_crypto.py -a decrypt original.dat.enc
diff original.dat original.dat  # Should show no differences

# Safe filename generation demonstration
python file_crypto.py -a encrypt existing_file.txt  # Creates existing_file_1.txt.enc
python file_crypto.py -a encrypt existing_file.txt  # Creates existing_file_2.txt.enc
```

### 🐍 Python API

You can integrate the encryption classes directly into your Python applications:

#### 🏭 Production AES Encryption

```python
from aes_encryption import AESEncryption
import logging

# Setup logging for production monitoring
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create AES encryption instance with enhanced security
aes = AESEncryption(
    password="your_secure_password",
    iterations=200000,      # High security iterations
    use_gcm=True,          # Authenticated encryption (recommended)
    logger=logger          # Production logging
)

# Encrypt sensitive data with automatic integrity protection
data = b"Confidential business data"
try:
    encrypted = aes.encrypt_data(data)
    decrypted = aes.decrypt_data(encrypted)
    logger.info("✅ Encryption/decryption successful")
except Exception as e:
    logger.error(f"❌ Encryption failed: {e}")

# Handle large files efficiently with chunked processing
try:
    aes.encrypt_file("large_dataset.csv", "encrypted_dataset.enc")
    aes.decrypt_file("encrypted_dataset.enc", "decrypted_dataset.csv")
    logger.info("✅ Large file processing completed")
except Exception as e:
    logger.error(f"❌ File processing failed: {e}")
```

#### 🛠️ Advanced Configuration Options

```python
from aes_encryption import AESEncryption
from error_handling import setup_logging

# Setup comprehensive logging
logger = setup_logging(verbose=True, log_file="crypto_operations.log")

# Maximum security configuration
max_security_aes = AESEncryption(
    password="ultra_secure_password!@#$",
    iterations=500000,        # Maximum recommended iterations
    salt_size=32,            # Larger salt for enhanced security
    use_gcm=True,            # Authenticated encryption
    logger=logger
)

# High-performance configuration for large files
high_perf_aes = AESEncryption(
    password="performance_optimized_pass",
    iterations=50000,         # Lower iterations for speed
    use_gcm=False,           # CBC mode for chunked processing
    logger=logger
)

# Process different file types appropriately
small_file_encrypted = max_security_aes.encrypt_data(b"Small sensitive data")
# Large files automatically use chunked processing
high_perf_aes.encrypt_file("multi_gb_file.zip", "encrypted_archive.enc")
```

#### 📚 Educational Caesar Cipher

```python
from caesar_cipher import CaesarCipher
from validation import ValidationError

# Text mode for educational demonstrations
text_cipher = CaesarCipher(shift=13, binary_mode=False)  # ROT13

try:
    # Demonstrate text encryption (preserves non-alphabetic characters)
    message = "Hello, World! 123"
    encrypted = text_cipher.encrypt_text(message)
    decrypted = text_cipher.decrypt_text(encrypted)
    
    print(f"Original:  {message}")
    print(f"ROT13:     {encrypted}")
    print(f"Decrypted: {decrypted}")
    
except ValidationError as e:
    print(f"❌ Validation error: {e}")

# Binary mode for understanding byte-level operations
binary_cipher = CaesarCipher(shift=42, binary_mode=True)

try:
    # Works on any file type
    binary_cipher.encrypt_file("any_file.bin", "encrypted_binary.caesar")
    binary_cipher.decrypt_file("encrypted_binary.caesar", "decrypted_binary.bin")
    
except ValidationError as e:
    print(f"❌ File operation error: {e}")
```

#### 🔧 Error Handling and Validation

```python
from error_handling import CryptoError, EncryptionError, DecryptionError
from validation import validate_password_strength, ValidationError

# Comprehensive error handling in production code
def secure_encrypt_file(input_path, output_path, password):
    try:
        # Validate password strength
        is_valid, warnings = validate_password_strength(password)
        if warnings:
            print("⚠️ Password warnings:")
            for warning in warnings:
                print(f"  • {warning}")
        
        # Create AES instance with error handling
        aes = AESEncryption(password, use_gcm=True)
        aes.encrypt_file(input_path, output_path)
        
        return True
        
    except ValidationError as e:
        print(f"❌ Input validation failed: {e}")
        return False
    except EncryptionError as e:
        print(f"❌ Encryption failed: {e}")
        return False
    except CryptoError as e:
        print(f"❌ Cryptographic error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

# Usage example
success = secure_encrypt_file("important.doc", "important.doc.enc", "MySecurePass123!")
if success:
    print("✅ File encrypted successfully")
else:
    print("❌ Encryption failed - check logs for details")
```

## 🧪 Testing & Quality Assurance

### Comprehensive Test Suite

Run our extensive test suite to verify all functionality:

```bash
# Run the comprehensive test suite (15 test cases, 100% coverage)
python test_comprehensive.py

# Run legacy compatibility tests
python test_encryption.py
```

**Test Coverage Includes:**
- ✅ **Edge Cases**: Empty files, large files (5MB+), binary data, unicode content
- ✅ **Error Conditions**: Wrong passwords, corrupted files, permission errors
- ✅ **Security Validation**: Password strength, file overwrite protection
- ✅ **Performance Testing**: Throughput benchmarks up to 310 MB/s
- ✅ **Integration Testing**: All encryption methods working together

### Performance Benchmarks

The test suite includes automated performance benchmarking:

```
🧪 COMPREHENSIVE FILE ENCRYPTION TEST SUITE
======================================================================
🔬 Running comprehensive test suite...
......✅ All 15 tests passed! (100% success rate)

🚀 PERFORMANCE BENCHMARKS
📊 0.1MB File: 9.4 MB/s encryption, 12.0 MB/s decryption
📊 1MB File: 93.4 MB/s encryption, 110.5 MB/s decryption  
📊 5MB File: 231.9 MB/s encryption, 309.8 MB/s decryption
```

### Quality Metrics

- **✅ 100% Test Pass Rate**: All 15 test cases consistently pass
- **✅ Comprehensive Coverage**: Tests edge cases, errors, and performance
- **✅ Cross-Platform**: Tested on Linux, macOS, and Windows environments
- **✅ Memory Efficient**: Constant memory usage regardless of file size
- **✅ Production Ready**: Extensive error handling and logging validation

## 🛡️ Security & Cryptographic Details

### 🔒 AES Encryption (Production Grade)

**Algorithm Specifications:**
- **AES-256-GCM**: Authenticated encryption providing both confidentiality and integrity
- **AES-256-CBC**: Traditional mode with HMAC for compatibility when needed
- **Key Derivation**: PBKDF2-HMAC-SHA256 with configurable iterations (default: 100,000)
- **Salt**: Cryptographically random 16-byte salt per encryption operation
- **IV/Nonce**: Random initialization vector/nonce for each encryption

**Security Features:**
- ✅ **Authenticated Encryption**: GCM mode prevents tampering and provides integrity verification
- ✅ **Memory Security**: Best-effort password clearing from memory after operations
- ✅ **Random Generation**: Cryptographically secure random number generation for salts/IVs
- ✅ **Key Stretching**: PBKDF2 with high iteration counts to prevent brute force attacks
- ✅ **No Key Reuse**: Fresh salt and IV for every encryption operation

**Performance & Security Balance:**
- **Small Files** (<64KB): Processed entirely in memory for optimal speed
- **Large Files** (>64KB): Chunked processing with constant memory usage
- **Iterations**: Default 100,000 PBKDF2 iterations (configurable up to 500,000+)

### ⚠️ Caesar Cipher (Educational Only)

**Important Security Warning:**
- 🚨 **NOT CRYPTOGRAPHICALLY SECURE** - For educational purposes only
- 🚨 **Easily Broken**: Vulnerable to frequency analysis and brute force (only 25-255 possible keys)
- 🚨 **No Integrity Protection**: Cannot detect tampering or corruption
- 🚨 **Pattern Preservation**: Statistical patterns remain visible in encrypted text

**Educational Value:**
- ✅ **Learning Tool**: Excellent for understanding basic encryption concepts
- ✅ **Historical Significance**: Demonstrates classical cryptographic methods
- ✅ **Implementation Study**: Shows contrast with modern encryption standards

### 🔐 Password Security Best Practices

**Recommended Password Criteria:**
- **Minimum Length**: 12+ characters (enforced: 8+ characters)
- **Complexity**: Mix of uppercase, lowercase, numbers, and special characters
- **Uniqueness**: Don't reuse passwords from other accounts/systems
- **Storage**: Use a reputable password manager
- **Generation**: Prefer randomly generated passwords over memorable phrases

**Password Strength Validation:**
The tool automatically validates password strength and provides specific recommendations:
```
⚠️ Password strength warnings (3 issues):
  • Password should be at least 12 characters long for better security
  • Include uppercase letters (A-Z) for stronger passwords  
  • Include special characters (!@#$%^&*) for maximum security
```

### 🏛️ Compliance & Standards

**Industry Standards Compliance:**
- **FIPS 197**: AES encryption algorithm compliance
- **NIST SP 800-38D**: GCM mode implementation following NIST guidelines
- **PKCS #5 v2.0**: PBKDF2 key derivation function compliance
- **RFC 3394**: Key wrap standards for additional security layers

**Audit Trail Features:**
- **Comprehensive Logging**: All operations logged with timestamps and details
- **Error Tracking**: Detailed error codes and messages for security audits
- **Operation Metadata**: File sizes, encryption modes, and performance metrics
- **Security Events**: Password validation results and security warnings logged

## 📁 Project Structure

```
File-Encryption-Decryption/
├── 🚀 Core Application
│   ├── file_crypto.py          # Main CLI application with enhanced argument parsing
│   ├── aes_encryption.py       # AES-256-GCM/CBC with chunked processing
│   ├── caesar_cipher.py        # Educational Caesar cipher (text/binary modes)
│   ├── validation.py           # Input validation and password strength checking
│   └── error_handling.py       # Comprehensive error handling and logging
├── 🧪 Testing & Quality
│   ├── test_comprehensive.py   # Complete test suite (15 tests, benchmarks)
│   └── test_encryption.py      # Legacy compatibility tests
├── 📋 Documentation & Config
│   ├── README.md              # This comprehensive documentation
│   └── requirements.txt        # Python dependencies with version specifications
└── 📊 Generated Files
    ├── *.enc                   # AES encrypted files
    ├── *.caesar               # Caesar cipher encrypted files
    └── *.log                   # Operation logs (when --log-file used)
```

### 🏗️ Architecture Overview

**Modular Design:**
- **Separation of Concerns**: Each module handles specific functionality
- **Error Handling**: Centralized error management with custom exception hierarchy
- **Logging**: Comprehensive logging system with configurable output levels
- **Validation**: Input sanitization and security parameter validation
- **Testing**: Extensive test coverage with performance benchmarking

**Performance Optimizations:**
- **Chunked Processing**: Memory-efficient large file handling
- **Streaming Operations**: Process files without loading entirely into memory
- **Optimized Algorithms**: AES-GCM for better performance than CBC+HMAC
- **Lazy Loading**: Import modules only when needed for faster startup

## 🤝 Contributing

We welcome contributions to improve this enterprise-grade encryption tool!

### Development Process
1. **Fork** the repository and create a feature branch
2. **Implement** your changes with appropriate error handling and logging
3. **Add Tests**: Include comprehensive test cases for new functionality
4. **Documentation**: Update README.md and add docstrings for new functions
5. **Performance**: Run benchmarks to ensure no performance regression
6. **Submit** a pull request with detailed description of changes

### Coding Standards
- **Type Hints**: All functions must include complete type annotations
- **Error Handling**: Use custom exception hierarchy from `error_handling.py`
- **Logging**: Include appropriate logging statements for debugging and monitoring
- **Testing**: Achieve 100% test coverage for new functionality
- **Security**: Follow cryptographic best practices and security guidelines

### Areas for Contribution
- 🔧 **Additional Encryption Algorithms**: ChaCha20-Poly1305, RSA hybrid encryption
- 🚀 **Performance Improvements**: Parallel processing, hardware acceleration
- 🔒 **Security Enhancements**: Key derivation improvements, additional validation
- 📱 **User Interface**: GUI application, web interface
- 📊 **Analytics**: Enhanced performance monitoring and reporting

## 📜 License

This project is open source and available under the **MIT License**.

### Commercial Use
- ✅ **Commercial Use Permitted**: Use in commercial applications and products
- ✅ **Modification Allowed**: Adapt and modify for your specific needs
- ✅ **Distribution Allowed**: Redistribute with proper attribution
- ✅ **Private Use**: Use internally within your organization

## ⚖️ Legal & Security Disclaimer

### Important Legal Notices

**Export Compliance:**
- This software contains cryptographic functionality that may be subject to export regulations
- Users are responsible for compliance with local laws regarding cryptographic software
- Check your jurisdiction's regulations before using in commercial products

**Security Responsibilities:**
- 🔒 **Production Use**: This tool provides strong encryption suitable for sensitive data
- 🔑 **Key Management**: Users are responsible for secure password/key management
- 💾 **Backup**: Always maintain secure backups of encryption keys and passwords
- 🔍 **Auditing**: Conduct security audits before deploying in production environments

**Liability Limitations:**
- This tool is provided "AS IS" without warranty of any kind
- Users assume all risks associated with the use of cryptographic software
- The authors are not liable for data loss, security breaches, or compliance violations
- Users must validate the tool meets their specific security requirements

**Ethical Use:**
- 🎯 **Legitimate Purposes**: Use only for lawful and ethical purposes
- 🚫 **Prohibited Uses**: Do not use to circumvent security measures or violate privacy
- 📋 **Compliance**: Ensure compliance with applicable laws and regulations
- 🔍 **Transparency**: Maintain appropriate audit trails and documentation

### Support & Security Issues

**Security Vulnerabilities:**
Report security issues responsibly to the maintainers before public disclosure.

**General Support:**
For questions, bug reports, and feature requests, please use the GitHub issue tracker.

---

**Version 3.0.0** | Built with ❤️ for secure, high-performance file encryption | Last Updated: September 19, 2025
