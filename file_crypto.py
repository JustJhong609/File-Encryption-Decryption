#!/usr/bin/env python3
"""
File Encryption and Decryption Tool

This program provides comprehensive file encryption and decryption functionality using:
1. Caesar Cipher (educational cipher with text/binary modes)
2. AES Encryption (industry-standard with GCM/CBC modes and configurable security)

Features:
- Chunked processing for large files (memory efficient)
- Comprehensive error handling and logging
- Password strength validation
- Authenticated encryption (AES-GCM)
- Smart output file naming
- Verbose operation logging

Author: File Encryption Tool
Version: 3.0.0
Date: September 19, 2025
"""

import os
import sys
import argparse
import getpass
import logging
import time
from pathlib import Path
from typing import Optional, Tuple

# Import encryption modules and utilities
from caesar_cipher import CaesarCipher
from aes_encryption import AESEncryption
from validation import (
    ValidationError, validate_password_strength, validate_file_path,
    generate_safe_output_filename, validate_encryption_method, validate_action
)
from error_handling import (
    setup_logging, safe_error_exit, CryptoError, EncryptionError, 
    DecryptionError, AuthenticationError, FileOperationError
)

# Version information
__version__ = "3.0.0"
__author__ = "File Encryption Tool"


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="file_crypto",
        description="Advanced file encryption and decryption tool with comprehensive security features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SECURITY NOTES:
  Caesar Cipher:
    ⚠️  EDUCATIONAL USE ONLY - Not cryptographically secure
    • Text mode: Shifts letters only (A-Z, a-z), preserves other characters
    • Binary mode: Shifts all bytes using modular arithmetic
    • Vulnerable to frequency analysis and brute force attacks
    
  AES Encryption:
    ✅ PRODUCTION READY - Industry standard encryption
    • AES-256 with GCM (authenticated) or CBC mode
    • PBKDF2 key derivation with configurable iterations
    • Chunked processing for large files (memory efficient)
    • Built-in integrity protection (GCM mode)

EXAMPLES:
  Basic Operations:
    %(prog)s -a encrypt document.txt                     # AES-GCM encrypt (secure)
    %(prog)s -a decrypt document.txt.enc                # AES decrypt
    %(prog)s -v -a encrypt --aes-cbc document.txt       # AES-CBC with verbose output
    
  Caesar Cipher (Educational):
    %(prog)s -a encrypt -m caesar -k 13 message.txt     # ROT13 text mode
    %(prog)s -a encrypt -m caesar --binary-caesar -k 42 image.jpg  # Binary mode
    
  Advanced Options:
    %(prog)s -a encrypt --aes-iterations 200000 --log-file crypto.log document.txt
    %(prog)s -a decrypt -v --password mypass secret.enc  # Less secure (password in CLI)

PERFORMANCE:
  • Files < 64KB: Processed in memory
  • Files > 64KB: Chunked processing (64KB chunks)
  • Large files: Progress logging available with -v flag
  
For more information, visit: https://github.com/JustJhong609/File-Encryption-Decryption
        """
    )
    
    # Positional arguments
    parser.add_argument(
        "file", 
        help="Path to the input file to encrypt or decrypt"
    )
    
    # Required arguments
    parser.add_argument(
        "-a", "--action", 
        choices=["encrypt", "decrypt"], 
        required=True,
        help="Action to perform: encrypt or decrypt the input file"
    )
    
    # Encryption method
    parser.add_argument(
        "-m", "--method", 
        choices=["caesar", "aes"], 
        default="aes",
        help="Encryption method (default: aes). Caesar cipher for education only!"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: auto-generated with safe naming)"
    )
    parser.add_argument(
        "--no-overwrite-check", 
        action="store_true",
        help="Disable safe output filename generation (may overwrite existing files)"
    )
    
    # Caesar cipher options
    caesar_group = parser.add_argument_group("Caesar Cipher Options (Educational Only)")
    caesar_group.add_argument(
        "-k", "--key", 
        type=int,
        help="Caesar shift value: 1-25 for text mode, 1-255 for binary mode"
    )
    caesar_group.add_argument(
        "--binary-caesar", 
        action="store_true",
        help="Use binary mode (shifts all bytes, not just letters)"
    )
    
    # AES encryption options
    aes_group = parser.add_argument_group("AES Encryption Options (Production Ready)")
    aes_group.add_argument(
        "--password",
        help="AES password (INSECURE: will prompt securely if omitted)"
    )
    aes_group.add_argument(
        "--aes-iterations", 
        type=int, 
        default=100000,
        help="PBKDF2 iterations for key derivation (default: 100,000, min: 10,000)"
    )
    aes_group.add_argument(
        "--aes-cbc", 
        action="store_true",
        help="Use AES-CBC mode instead of GCM (less secure, for compatibility)"
    )
    
    # Security and validation options
    security_group = parser.add_argument_group("Security Options")
    security_group.add_argument(
        "--weak-password-ok", 
        action="store_true",
        help="Skip password strength validation warnings"
    )
    
    # Logging and debugging options
    debug_group = parser.add_argument_group("Logging and Debug Options")
    debug_group.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose output with detailed progress information"
    )
    debug_group.add_argument(
        "--log-file",
        type=Path,
        help="Write detailed logs to specified file"
    )
    debug_group.add_argument(
        "--version", 
        action="version",
        version=f"%(prog)s {__version__} by {__author__}",
        help="Show version information and exit"
    )
    
    return parser


def main() -> None:
    """Main function to handle command line arguments and execute encryption/decryption."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(
        verbose=args.verbose,
        log_file=args.log_file if hasattr(args, 'log_file') else None
    )
    
    logger.info(f"File Crypto Tool v{__version__} starting...")
    logger.debug(f"Arguments: {vars(args)}")
    
    start_time = time.time()
    
    try:
        # Print security warning for Caesar cipher
        if args.method == "caesar":
            logger.warning("⚠️  Caesar cipher selected - FOR EDUCATIONAL USE ONLY")
            logger.warning("   This method is NOT cryptographically secure!")
            logger.warning("   Use AES encryption for protecting sensitive data.")
            
            if not args.verbose:
                print("⚠️  WARNING: Caesar cipher is not secure! Use for education only.")
        
        # Validate arguments
        validate_action(args.action)
        validate_encryption_method(args.method)
        
        # Validate and prepare file paths
        input_file, output_file = _prepare_file_paths(args, logger)
        
        # Execute the requested operation
        if args.method == "caesar":
            _execute_caesar_operation(args, input_file, output_file, logger)
        elif args.method == "aes":
            _execute_aes_operation(args, input_file, output_file, logger)
        
        # Log total operation time
        total_time = time.time() - start_time
        logger.info(f"Total operation completed in {total_time:.2f} seconds")
        
        if args.verbose:
            print(f"\n✅ Operation completed successfully in {total_time:.2f} seconds")
        
    except CryptoError as e:
        safe_error_exit(e, logger)
    except ValidationError as e:
        safe_error_exit(e, logger)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        print("\n⚠️  Operation cancelled by user.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        safe_error_exit(e, logger)


def _prepare_file_paths(args, logger: logging.Logger) -> Tuple[Path, Path]:
    """Prepare and validate input and output file paths."""
    # Validate input file
    input_file = validate_file_path(args.file, check_exists=True, check_readable=True)
    logger.info(f"Input file: {input_file}")
    
    # Determine output file
    if args.output:
        output_file = Path(args.output)
        if not args.no_overwrite_check and output_file.exists():
            print(f"⚠️  Warning: Output file '{output_file}' already exists.")
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
            output_file = _generate_decrypt_filename(input_file, args, logger)
    
    logger.info(f"Output file: {output_file}")
    return input_file, output_file


def _generate_decrypt_filename(input_file: Path, args, logger: logging.Logger) -> Path:
    """Generate appropriate filename for decrypted output."""
    if args.method == "aes" and str(input_file).endswith(".enc"):
        base_name = str(input_file)[:-4]
    elif args.method == "caesar" and str(input_file).endswith(".caesar"):
        base_name = str(input_file)[:-7]
    else:
        base_name = str(input_file) + ".decrypted"
    
    output_file = Path(base_name)
    if not args.no_overwrite_check and output_file.exists():
        # Generate safe name for decryption
        counter = 1
        while output_file.exists():
            if base_name.endswith('.decrypted'):
                output_file = Path(f"{base_name}_{counter}")
            else:
                ext = Path(base_name).suffix
                stem = Path(base_name).stem
                output_file = Path(base_name).parent / f"{stem}_{counter}{ext}"
            counter += 1
        logger.debug(f"Generated unique output filename: {output_file}")
    
    return output_file


def _execute_caesar_operation(args, input_file: Path, output_file: Path, 
                            logger: logging.Logger) -> None:
    """Execute Caesar cipher encryption or decryption."""
    # Get Caesar cipher key
    if args.key is None:
        max_key = 255 if args.binary_caesar else 25
        mode_desc = "binary" if args.binary_caesar else "text"
        prompt = f"Enter Caesar cipher key (1-{max_key}) for {mode_desc} mode: "
        try:
            key = int(input(prompt))
        except ValueError:
            raise ValidationError("Caesar cipher key must be an integer")
    else:
        key = args.key
    
    logger.info(f"Caesar cipher key: {key} ({'binary' if args.binary_caesar else 'text'} mode)")
    
    # Create cipher instance
    cipher = CaesarCipher(key, binary_mode=args.binary_caesar)
    
    # Execute operation
    if args.action == "encrypt":
        cipher.encrypt_file(input_file, output_file)
        print(f"✅ File encrypted successfully: {output_file}")
        logger.info("Caesar encryption completed")
    else:
        cipher.decrypt_file(input_file, output_file)
        print(f"✅ File decrypted successfully: {output_file}")
        logger.info("Caesar decryption completed")


def _execute_aes_operation(args, input_file: Path, output_file: Path, 
                         logger: logging.Logger) -> None:
    """Execute AES encryption or decryption."""
    # Get password
    if args.password:
        password = args.password
        logger.warning("Password provided via command line (less secure)")
        print("⚠️  Warning: Providing password via command line is less secure.")
        print("   Consider omitting --password to be prompted securely.")
    else:
        password = getpass.getpass("🔐 Enter password for AES encryption: ")
        logger.debug("Password obtained securely via getpass")
    
    # Validate password strength
    if not args.weak_password_ok:
        try:
            is_valid, warnings = validate_password_strength(password)
            if warnings:
                print(f"\n⚠️  Password strength warnings ({len(warnings)} issues):")
                for warning in warnings:
                    print(f"   • {warning}")
                
                if not args.password:  # Only prompt if password wasn't provided via CLI
                    response = input("\nContinue with this password? (y/N): ").strip().lower()
                    if response not in ['y', 'yes']:
                        print("Operation cancelled.")
                        sys.exit(0)
                logger.info(f"Password validation: {len(warnings)} warnings")
            else:
                logger.info("Password validation: strong password")
        except ValidationError as e:
            logger.error(f"Password validation failed: {e}")
            raise
    else:
        logger.debug("Password strength validation skipped")
    
    # Create AES encryption instance
    use_gcm = not args.aes_cbc  # Default to GCM unless CBC explicitly requested
    aes = AESEncryption(
        password, 
        iterations=args.aes_iterations, 
        use_gcm=use_gcm,
        logger=logger
    )
    
    # Execute operation
    if args.action == "encrypt":
        aes.encrypt_file(input_file, output_file)
        mode = "GCM" if use_gcm else "CBC"
        print(f"✅ File encrypted successfully: {output_file}")
        print(f"🔒 Security: AES-256-{mode}, {args.aes_iterations:,} PBKDF2 iterations")
        logger.info(f"AES-{mode} encryption completed")
    else:
        aes.decrypt_file(input_file, output_file)
        print(f"✅ File decrypted successfully: {output_file}")
        logger.info("AES decryption completed")


if __name__ == "__main__":
    main()
