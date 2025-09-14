#!/usr/bin/env python3
"""
File Encryption and Decryption Tool

This program provides file encryption and decryption functionality using:
1. Caesar Cipher (simple substitution cipher for text or byte-level for binary)
2. AES Encryption (Advanced Encryption Standard with configurable security)

Author: File Encryption Tool
Date: September 14, 2025
"""

import os
import sys
import argparse
import getpass
from pathlib import Path

# Import encryption modules and validation
from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption
from validation import (
    ValidationError, validate_password_strength, validate_file_path,
    generate_safe_output_filename, validate_encryption_method, validate_action
)


def main():
    """Main function to handle command line arguments and execute encryption/decryption."""
    
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files using Caesar cipher or AES encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Notes:
  Caesar cipher: Educational/simple obfuscation only. Not secure for sensitive data.
  AES encryption: Industry-standard, suitable for sensitive data with strong passwords.

Examples:
  %(prog)s -a encrypt document.txt                    # AES encrypt with prompted password
  %(prog)s -a encrypt -m caesar -k 13 message.txt    # Caesar cipher (ROT13)
  %(prog)s -a decrypt secret.txt.enc                 # AES decrypt
  %(prog)s -a encrypt --binary-caesar -k 42 image.jpg # Binary Caesar cipher
        """
    )
    
    # Add command line arguments
    parser.add_argument("file", help="Path to the input file")
    parser.add_argument("-o", "--output", help="Output file path (optional, auto-generated if not specified)")
    parser.add_argument("-m", "--method", choices=["caesar", "aes"], 
                       default="aes", help="Encryption method (default: aes)")
    parser.add_argument("-a", "--action", choices=["encrypt", "decrypt"], 
                       required=True, help="Action to perform")
    parser.add_argument("-k", "--key", type=int, 
                       help="Caesar cipher key (shift value: 1-25 for text, 1-255 for binary)")
    parser.add_argument("--password", 
                       help="Password for AES encryption (will prompt securely if not provided)")
    parser.add_argument("--binary-caesar", action="store_true",
                       help="Use binary mode for Caesar cipher (operates on all bytes)")
    parser.add_argument("--aes-iterations", type=int, default=100000,
                       help="PBKDF2 iterations for AES (default: 100000)")
    parser.add_argument("--no-overwrite-check", action="store_true",
                       help="Disable automatic output filename generation (may overwrite files)")
    parser.add_argument("--weak-password-ok", action="store_true",
                       help="Allow weak passwords without warnings")
    
    args = parser.parse_args()
    
    try:
        # Validate arguments
        validate_action(args.action)
        validate_encryption_method(args.method)
        
        # Validate input file
        input_file = validate_file_path(args.file, check_exists=True, check_readable=True)
        
        # Determine output file
        if args.output:
            output_file = Path(args.output)
            if not args.no_overwrite_check and output_file.exists():
                print(f"Warning: Output file '{output_file}' already exists.")
                response = input("Do you want to overwrite it? (y/N): ").strip().lower()
                if response not in ['y', 'yes']:
                    print("Operation cancelled.")
                    sys.exit(0)
        else:
            # Auto-generate output filename
            if args.action == "encrypt":
                suffix = ".enc" if args.method == "aes" else ".caesar"
                if args.no_overwrite_check:
                    output_file = input_file.with_suffix(input_file.suffix + suffix)
                else:
                    output_file = generate_safe_output_filename(input_file, suffix)
            else:  # decrypt
                if args.method == "aes" and str(input_file).endswith(".enc"):
                    base_name = str(input_file)[:-4]
                elif args.method == "caesar" and str(input_file).endswith(".caesar"):
                    base_name = str(input_file)[:-7]
                else:
                    base_name = str(input_file) + ".decrypted"
                
                output_file = Path(base_name)
                if not args.no_overwrite_check and output_file.exists():
                    # Generate safe name for decryption too
                    counter = 1
                    while output_file.exists():
                        if base_name.endswith('.decrypted'):
                            output_file = Path(f"{base_name}_{counter}")
                        else:
                            ext = output_file.suffix
                            stem = output_file.stem
                            output_file = output_file.parent / f"{stem}_{counter}{ext}"
                        counter += 1
    
        # Process encryption/decryption
        if args.method == "caesar":
            # Caesar cipher encryption/decryption
            if args.key is None:
                max_key = 255 if args.binary_caesar else 25
                prompt = f"Enter Caesar cipher key (1-{max_key}): "
                try:
                    key = int(input(prompt))
                except ValueError:
                    raise ValidationError("Caesar cipher key must be an integer")
            else:
                key = args.key
            
            cipher = CaesarCipher(key, binary_mode=args.binary_caesar)
            
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
                print("Warning: Providing password via command line is less secure.")
                print("Consider omitting --password to be prompted securely.")
            else:
                password = getpass.getpass("Enter password for AES encryption: ")
            
            # Validate password strength
            if not args.weak_password_ok:
                try:
                    is_valid, warnings = validate_password_strength(password)
                    if warnings:
                        print("\nPassword strength warnings:")
                        for warning in warnings:
                            print(f"  - {warning}")
                        
                        if not args.password:  # Only prompt if password wasn't provided via CLI
                            response = input("\nContinue with this password? (y/N): ").strip().lower()
                            if response not in ['y', 'yes']:
                                print("Operation cancelled.")
                                sys.exit(0)
                except ValidationError as e:
                    print(f"Password validation error: {e}")
                    sys.exit(1)
            
            # Create AES encryption instance with custom parameters
            aes = AESEncryption(password, iterations=args.aes_iterations)
            
            if args.action == "encrypt":
                aes.encrypt_file(input_file, output_file)
                print(f"File encrypted successfully: {output_file}")
                print(f"Security: {args.aes_iterations} PBKDF2 iterations used")
            else:
                aes.decrypt_file(input_file, output_file)
                print(f"File decrypted successfully: {output_file}")
    
    except ValidationError as e:
        print(f"Validation Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
