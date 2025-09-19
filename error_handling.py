"""
Enhanced Error Handling Module

This module provides comprehensive error handling utilities with user-friendly
error messages, logging capabilities, and specific exception types for different
error scenarios in the file encryption/decryption system.
"""

import logging
import sys
from pathlib import Path
from typing import Optional, Union, Any
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels for consistent error reporting."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class CryptoError(Exception):
    """Base exception class for all cryptographic operations."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 severity: ErrorSeverity = ErrorSeverity.ERROR):
        self.message = message
        self.error_code = error_code
        self.severity = severity
        super().__init__(self.message)


class FileOperationError(CryptoError):
    """Exception for file-related operations."""
    pass


class ValidationError(CryptoError):
    """Exception for input validation failures."""
    pass


class EncryptionError(CryptoError):
    """Exception for encryption-related failures."""
    pass


class DecryptionError(CryptoError):
    """Exception for decryption-related failures."""
    pass


class AuthenticationError(CryptoError):
    """Exception for authentication failures (wrong password, corrupted data)."""
    pass


class UnsupportedOperationError(CryptoError):
    """Exception for unsupported operations or file types."""
    pass


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> logging.Logger:
    """
    Set up logging configuration for the application.
    
    Args:
        verbose: Enable verbose logging
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('file_crypto')
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set logging level
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def handle_file_not_found(file_path: Union[str, Path]) -> FileOperationError:
    """Create user-friendly error for file not found."""
    return FileOperationError(
        f"File not found: '{file_path}'\n"
        f"Please check that the file exists and the path is correct.",
        error_code="FILE_NOT_FOUND",
        severity=ErrorSeverity.ERROR
    )


def handle_permission_denied(file_path: Union[str, Path], operation: str) -> FileOperationError:
    """Create user-friendly error for permission denied."""
    return FileOperationError(
        f"Permission denied when trying to {operation} file: '{file_path}'\n"
        f"Please check file permissions or run with appropriate privileges.",
        error_code="PERMISSION_DENIED",
        severity=ErrorSeverity.ERROR
    )


def handle_invalid_decryption_key() -> DecryptionError:
    """Create user-friendly error for invalid decryption key/password."""
    return DecryptionError(
        "Decryption failed: Invalid password or decryption key.\n"
        "Please check your password and try again. If the file was encrypted\n"
        "with a different password or method, use the correct credentials.",
        error_code="INVALID_CREDENTIALS",
        severity=ErrorSeverity.ERROR
    )


def handle_corrupted_file(file_path: Union[str, Path], details: Optional[str] = None) -> DecryptionError:
    """Create user-friendly error for corrupted input files."""
    message = f"File appears to be corrupted or not properly encrypted: '{file_path}'"
    if details:
        message += f"\nTechnical details: {details}"
    message += "\nPlease verify the file integrity and encryption method used."
    
    return DecryptionError(
        message,
        error_code="CORRUPTED_FILE",
        severity=ErrorSeverity.ERROR
    )


def handle_unsupported_file_type(file_path: Union[str, Path], 
                                operation: str) -> UnsupportedOperationError:
    """Create user-friendly error for unsupported file types."""
    return UnsupportedOperationError(
        f"Unsupported file type or mode for {operation}: '{file_path}'\n"
        f"This operation is not supported for this file type.\n"
        f"For binary files, consider using Caesar cipher in binary mode (--binary-caesar).",
        error_code="UNSUPPORTED_FILE_TYPE",
        severity=ErrorSeverity.ERROR
    )


def handle_large_file_warning(file_path: Union[str, Path], size_mb: float) -> None:
    """Log warning for large files."""
    logger = logging.getLogger('file_crypto')
    logger.warning(
        f"Processing large file: '{file_path}' ({size_mb:.1f} MB)\n"
        f"This may take some time and consume significant memory."
    )


def safe_error_exit(error: Exception, logger: Optional[logging.Logger] = None) -> None:
    """
    Safely exit the application with proper error reporting.
    
    Args:
        error: Exception that occurred
        logger: Optional logger for error reporting
    """
    if logger:
        logger.error(f"Application error: {str(error)}")
    
    if isinstance(error, CryptoError):
        print(f"\n{error.severity.value}: {error.message}")
        if error.error_code:
            print(f"Error Code: {error.error_code}")
    else:
        print(f"\nUnexpected Error: {str(error)}")
        print("Please report this issue with the steps to reproduce it.")
    
    sys.exit(1)


def validate_file_access(file_path: Union[str, Path], 
                        operation: str = "access") -> Path:
    """
    Validate file access with comprehensive error handling.
    
    Args:
        file_path: Path to validate
        operation: Type of operation (read, write, access)
        
    Returns:
        Validated Path object
        
    Raises:
        FileOperationError: If file access validation fails
    """
    path = Path(file_path)
    
    try:
        if operation in ("read", "access") and not path.exists():
            raise handle_file_not_found(path)
        
        if operation in ("read", "access") and not path.is_file():
            raise FileOperationError(
                f"Path is not a regular file: '{path}'",
                error_code="NOT_A_FILE"
            )
        
        # Check if file is too large (>1GB warning)
        if path.exists() and operation == "read":
            size_bytes = path.stat().st_size
            size_mb = size_bytes / (1024 * 1024)
            if size_mb > 1024:  # 1GB
                handle_large_file_warning(path, size_mb)
        
        return path
        
    except PermissionError:
        raise handle_permission_denied(path, operation)
    except OSError as e:
        raise FileOperationError(
            f"File system error accessing '{path}': {str(e)}",
            error_code="FILESYSTEM_ERROR"
        )


def log_operation_start(operation: str, file_path: Path, 
                       method: str, logger: logging.Logger) -> None:
    """Log the start of an encryption/decryption operation."""
    logger.info(f"Starting {operation} operation")
    logger.info(f"  File: {file_path}")
    logger.info(f"  Method: {method}")
    logger.info(f"  File size: {file_path.stat().st_size} bytes")


def log_operation_complete(operation: str, output_path: Path, 
                          elapsed_time: float, logger: logging.Logger) -> None:
    """Log the completion of an encryption/decryption operation."""
    logger.info(f"{operation.capitalize()} completed successfully")
    logger.info(f"  Output: {output_path}")
    logger.info(f"  Output size: {output_path.stat().st_size} bytes")
    logger.info(f"  Time taken: {elapsed_time:.2f} seconds")