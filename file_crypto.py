#!/usr/bin/env python3
"""
File Encryption and Decryption Tool

This program provides file encryption and decryption functionality using:
1. Caesar Cipher (simple substitution cipher)
2. AES Encryption (Advanced Encryption Standard)

Author: File Encryption Tool
Date: September 7, 2025
"""

import os
import sys
import argparse
import getpass
from pathlib import Path

# Import encryption modules
from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption


def main():
    """Main function to handle command line arguments and execute encryption/decryption."""
    
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files using Caesar cipher or AES encryption"
    )
    
    # Add command line arguments
    parser.add_argument("file", help="Path to the input file")
    parser.add_argument("-o", "--output", help="Output file path (optional)")
    parser.add_argument("-m", "--method", choices=["caesar", "aes"], 
                       default="aes", help="Encryption method (default: aes)")
    parser.add_argument("-a", "--action", choices=["encrypt", "decrypt"], 
                       required=True, help="Action to perform")
    parser.add_argument("-k", "--key", type=int, 
                       help="Caesar cipher key (shift value, 1-25)")
    parser.add_argument("--password", 
                       help="Password for AES encryption (will prompt if not provided)")
    
    args = parser.parse_args()
    
    # Validate input file
    input_file = Path(args.file)
    if not input_file.exists():
        print(f"Error: Input file '{args.file}' does not exist.")
        sys.exit(1)
    
    # Determine output file
    if args.output:
        output_file = Path(args.output)
    else:
        if args.action == "encrypt":
            suffix = ".enc" if args.method == "aes" else ".caesar"
            output_file = input_file.with_suffix(input_file.suffix + suffix)
        else:  # decrypt
            if args.method == "aes" and str(input_file).endswith(".enc"):
                output_file = Path(str(input_file)[:-4])
            elif args.method == "caesar" and str(input_file).endswith(".caesar"):
                output_file = Path(str(input_file)[:-7])
            else:
                output_file = input_file.with_suffix(".decrypted" + input_file.suffix)
    
    try:
        if args.method == "caesar":
            # Caesar cipher encryption/decryption
            if args.key is None:
                key = int(input("Enter Caesar cipher key (1-25): "))
            else:
                key = args.key
            
            if not (1 <= key <= 25):
                print("Error: Caesar cipher key must be between 1 and 25.")
                sys.exit(1)
            
            cipher = CaesarCipher(key)
            
            if args.action == "encrypt":
                cipher.encrypt_file(input_file, output_file)
                print(f"File encrypted successfully: {output_file}")
            else:
                cipher.decrypt_file(input_file, output_file)
                print(f"File decrypted successfully: {output_file}")
        
        elif args.method == "aes":
            # AES encryption/decryption
            if args.password:
                password = args.password
            else:
                password = getpass.getpass("Enter password for AES encryption: ")
            
            if len(password) < 8:
                print("Error: Password must be at least 8 characters long.")
                sys.exit(1)
            
            aes = AESEncryption(password)
            
            if args.action == "encrypt":
                aes.encrypt_file(input_file, output_file)
                print(f"File encrypted successfully: {output_file}")
            else:
                aes.decrypt_file(input_file, output_file)
                print(f"File decrypted successfully: {output_file}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
