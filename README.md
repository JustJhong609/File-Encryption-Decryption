# File Encryption and Decryption Tool

A comprehensive Python tool for encrypting and decrypting files using both simple Caesar cipher and robust AES (Advanced Encryption Standard) encryption algorithms.

## Features

- **Caesar Cipher**: Simple substitution cipher with customizable shift values (1-25)
- **AES-256 Encryption**: Industry-standard encryption with password-based key derivation
- **File Support**: Works with both text and binary files
- **Command-line Interface**: Easy-to-use CLI with various options
- **Secure Implementation**: Uses cryptography library for AES with PBKDF2 key derivation

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

- `file`: Input file path (required)
- `-a, --action`: Action to perform (`encrypt` or `decrypt`) (required)
- `-m, --method`: Encryption method (`caesar` or `aes`) (default: `aes`)
- `-o, --output`: Output file path (optional, auto-generated if not specified)
- `-k, --key`: Caesar cipher shift value (1-25, required for Caesar cipher)
- `--password`: AES password (optional, will prompt if not provided)

#### Examples

```bash
# AES encryption with custom output file
python file_crypto.py -a encrypt -o encrypted_data.enc document.pdf

# Caesar cipher with shift 13 (ROT13)
python file_crypto.py -a encrypt -m caesar -k 13 message.txt

# AES decryption with password provided
python file_crypto.py -a decrypt --password mypassword secret.txt.enc

# Caesar decryption
python file_crypto.py -a decrypt -m caesar -k 13 message.txt.caesar
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

# AES encryption (recommended for sensitive data)
python file_crypto.py -a encrypt myfile.txt
python file_crypto.py -a decrypt myfile.txt.enc

# Caesar cipher (educational/simple obfuscation)
python file_crypto.py -a encrypt -m caesar -k 13 myfile.txt
python file_crypto.py -a decrypt -m caesar -k 13 myfile.txt.caesar

# With custom output and password
python file_crypto.py -a encrypt -o secure.enc --password mypass document.pdf


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