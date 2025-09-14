"""
Input validation utilities for file encryption/decryption tool.

This module provides comprehensive validation functions for user inputs,
passwords, file paths, and encryption parameters.
"""

import re
import os
from pathlib import Path


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_caesar_shift(shift):
    """
    Validate Caesar cipher shift value.
    
    Args:
        shift (int): Shift value to validate
        
    Returns:
        int: Validated shift value
        
    Raises:
        ValidationError: If shift is invalid
    """
    if not isinstance(shift, int):
        raise ValidationError("Caesar cipher shift must be an integer")
    
    if not (1 <= shift <= 25):
        raise ValidationError(
            f"Caesar cipher shift must be between 1 and 25, got {shift}. "
            "Note: shift of 26 is equivalent to no shift."
        )
    
    return shift


def validate_password_strength(password):
    """
    Validate AES password strength and provide security recommendations.
    
    Args:
        password (str): Password to validate
        
    Returns:
        tuple: (is_valid, warnings_list)
    """
    warnings = []
    
    # Minimum length check
    if len(password) < 8:
        raise ValidationError(
            "Password must be at least 8 characters long for security. "
            f"Current length: {len(password)}"
        )
    
    # Strength checks (warnings, not errors)
    if len(password) < 12:
        warnings.append("Consider using a password of 12+ characters for better security")
    
    if not re.search(r'[a-z]', password):
        warnings.append("Password should contain lowercase letters")
    
    if not re.search(r'[A-Z]', password):
        warnings.append("Password should contain uppercase letters")
    
    if not re.search(r'\d', password):
        warnings.append("Password should contain numbers")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        warnings.append("Password should contain special characters")
    
    # Check for common weak patterns
    if password.lower() in ['password', '12345678', 'qwerty', 'admin', 'test']:
        warnings.append("Avoid common passwords")
    
    if re.search(r'(.)\1{2,}', password):  # 3+ repeated characters
        warnings.append("Avoid repeated character patterns")
    
    return True, warnings


def validate_file_path(file_path, check_exists=True, check_readable=True, check_writable=False):
    """
    Validate file path and permissions.
    
    Args:
        file_path (str/Path): Path to validate
        check_exists (bool): Whether file must exist
        check_readable (bool): Whether file must be readable
        check_writable (bool): Whether file must be writable
        
    Returns:
        Path: Validated Path object
        
    Raises:
        ValidationError: If validation fails
    """
    path = Path(file_path)
    
    if check_exists and not path.exists():
        raise ValidationError(f"File does not exist: {path}")
    
    if path.exists():
        if not path.is_file():
            raise ValidationError(f"Path is not a file: {path}")
        
        if check_readable and not os.access(path, os.R_OK):
            raise ValidationError(f"File is not readable: {path}")
        
        if check_writable and not os.access(path, os.W_OK):
            raise ValidationError(f"File is not writable: {path}")
    
    # Check if parent directory is writable for new files
    if not path.exists() and check_writable:
        parent = path.parent
        if not parent.exists():
            raise ValidationError(f"Parent directory does not exist: {parent}")
        
        if not os.access(parent, os.W_OK):
            raise ValidationError(f"Cannot write to directory: {parent}")
    
    return path


def generate_safe_output_filename(input_path, suffix, max_attempts=1000):
    """
    Generate a safe output filename that doesn't overwrite existing files.
    
    Args:
        input_path (Path): Input file path
        suffix (str): Suffix to add (e.g., '.enc', '.caesar')
        max_attempts (int): Maximum attempts to find unique name
        
    Returns:
        Path: Safe output file path
        
    Raises:
        ValidationError: If unable to generate unique filename
    """
    input_path = Path(input_path)
    base_output = input_path.with_suffix(input_path.suffix + suffix)
    
    if not base_output.exists():
        return base_output
    
    # Try numbered variants
    for i in range(1, max_attempts + 1):
        stem = input_path.stem
        new_name = f"{stem}_{i}{input_path.suffix}{suffix}"
        candidate = input_path.parent / new_name
        
        if not candidate.exists():
            return candidate
    
    raise ValidationError(
        f"Unable to generate unique output filename after {max_attempts} attempts. "
        f"Please specify a custom output path or clean up existing files."
    )


def validate_encryption_method(method):
    """
    Validate encryption method.
    
    Args:
        method (str): Encryption method
        
    Returns:
        str: Validated method
        
    Raises:
        ValidationError: If method is invalid
    """
    valid_methods = ['caesar', 'aes']
    if method not in valid_methods:
        raise ValidationError(
            f"Invalid encryption method: {method}. "
            f"Valid methods: {', '.join(valid_methods)}"
        )
    return method


def validate_action(action):
    """
    Validate action type.
    
    Args:
        action (str): Action to perform
        
    Returns:
        str: Validated action
        
    Raises:
        ValidationError: If action is invalid
    """
    valid_actions = ['encrypt', 'decrypt']
    if action not in valid_actions:
        raise ValidationError(
            f"Invalid action: {action}. "
            f"Valid actions: {', '.join(valid_actions)}"
        )
    return action