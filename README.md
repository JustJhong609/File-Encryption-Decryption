# File Encryption and Decryption Tool

A comprehensive Python tool for encrypting and decrypting files using both simple Caesar cipher and robust AES (Advanced Encryption Standard) encryption algorithms.

## Features

### Encryption Methods
- **Caesar Cipher**: Simple substitution cipher with two modes:
  - **Text Mode**: Shifts letters only (A-Z, a-z), preserves other characters (shift: 1-25)  
  - **Binary Mode**: Shifts all bytes using modular arithmetic (shift: 1-255)
- **AES-256 Encryption**: Industry-standard encryption with configurable security parameters

### Security Enhancements
- **Password Strength Validation**: Comprehensive validation with security recommendations
- **Configurable PBKDF2**: Customizable iterations (default: 100,000) and salt size
- **Secure Input**: Uses getpass for password input without command-line echoing
- **Safe File Handling**: Automatic output filename generation to prevent overwrites

### Robust Error Handling
- **Input Validation**: Comprehensive validation of all parameters and file paths
- **Permission Checks**: Validates file read/write permissions before processing
- **Graceful Failure**: Clear error messages and proper cleanup on failures

### Advanced CLI Features
- **Smart Filename Generation**: Automatic safe output filenames with conflict resolution
- **Multiple Security Levels**: Configurable encryption parameters for different use cases
- **Comprehensive Help**: Detailed usage examples and security notes

## Requirements

- Python 3.7+
- cryptography library

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

## Usage

### Command Line Interface

The main script `file_crypto.py` provides a command-line interface for file encryption and decryption.

#### Basic Usage

```bash
# Encrypt a file using AES (default)
python file_crypto.py -a encrypt myfile.txt

# Decrypt a file using AES
python file_crypto.py -a decrypt myfile.txt.enc

# Encrypt using Caesar cipher
python file_crypto.py -a encrypt -m caesar -k 5 myfile.txt

# Decrypt using Caesar cipher
python file_crypto.py -a decrypt -m caesar -k 5 myfile.txt.caesar
```

#### Command Line Arguments

**Required:**
- `file`: Input file path
- `-a, --action`: Action to perform (`encrypt` or `decrypt`)

**Encryption Method:**
- `-m, --method`: Encryption method (`caesar` or `aes`) (default: `aes`)

**Output Options:**
- `-o, --output`: Output file path (optional, auto-generated with conflict resolution if not specified)
- `--no-overwrite-check`: Disable safe filename generation (may overwrite files)

**Caesar Cipher Options:**
- `-k, --key`: Shift value (1-25 for text mode, 1-255 for binary mode)
- `--binary-caesar`: Enable binary mode (operates on all bytes, not just letters)

**AES Encryption Options:**
- `--password`: Password (optional, will prompt securely if not provided)
- `--aes-iterations`: PBKDF2 iterations (default: 100,000)
- `--weak-password-ok`: Skip password strength warnings

#### Examples

```bash
# AES encryption with custom output file and security parameters
python file_crypto.py -a encrypt -o encrypted_data.enc --aes-iterations 200000 document.pdf

# Caesar cipher with shift 13 (ROT13) - text mode
python file_crypto.py -a encrypt -m caesar -k 13 message.txt

# Binary Caesar cipher for any file type
python file_crypto.py -a encrypt -m caesar --binary-caesar -k 42 image.jpg

# AES decryption with password provided (less secure)
python file_crypto.py -a decrypt --password mypassword secret.txt.enc

# AES decryption with secure password prompt
python file_crypto.py -a decrypt secret.txt.enc

# Caesar decryption (auto-detects mode based on encryption)
python file_crypto.py -a decrypt -m caesar -k 13 message.txt.caesar

# Disable overwrite protection (use with caution)
python file_crypto.py -a encrypt --no-overwrite-check data.txt
```

### Python API

You can also use the encryption classes directly in your Python code:

#### Caesar Cipher

```python
from caesar_cipher import CaesarCipher

# Create cipher with shift of 5
cipher = CaesarCipher(5)

# Encrypt/decrypt text
encrypted = cipher.encrypt_text("Hello, World!")
decrypted = cipher.decrypt_text(encrypted)

# Encrypt/decrypt files
cipher.encrypt_file("input.txt", "output.caesar")
cipher.decrypt_file("output.caesar", "decrypted.txt")
```

#### AES Encryption

```python
from aes_encryption import AESEncryption

# Create AES encryption instance
aes = AESEncryption("your_secure_password")

# Encrypt/decrypt data
data = b"Secret message"
encrypted = aes.encrypt_data(data)
decrypted = aes.decrypt_data(encrypted)

# Encrypt/decrypt files
aes.encrypt_file("input.txt", "output.enc")
aes.decrypt_file("output.enc", "decrypted.txt")
```

## Testing

Run the test suite to verify functionality:

```bash
python test_encryption.py
```

This will test both encryption methods with various file types and edge cases.

## Security Notes

### Caesar Cipher
- **Simple and fast** but **not secure** for sensitive data
- Easily breakable with frequency analysis
- Best used for educational purposes or simple obfuscation

### AES Encryption
- **Industry-standard encryption** suitable for sensitive data
- Uses AES-256 in CBC mode with PBKDF2 key derivation
- 100,000 iterations for key derivation (recommended minimum)
- Random salt and IV for each encryption operation
- **Use strong passwords** (at least 8 characters, preferably longer with mixed characters)

## File Structure

```
File-Encryption-Decryption/
├── file_crypto.py          # Main CLI application
├── caesar_cipher.py        # Caesar cipher implementation
├── aes_encryption.py       # AES encryption implementation
├── test_encryption.py      # Test suite
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is provided for educational and legitimate use cases only. Users are responsible for ensuring they have the right to encrypt/decrypt files and comply with applicable laws and regulations.
