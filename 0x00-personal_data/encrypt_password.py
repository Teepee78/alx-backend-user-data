#!/usr/bin/env python3
"""Bcrypt usage"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password

    Args:
        password (str): password to hash

    Returns:
        bytes: hashed password
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


def is_valid(hashed_password: str, password: str) -> bool:
    """Checks if a password is valid

    Args:
        hashed_password (str): hashed password
        password (str): password

    Returns:
        bool: True if password is valid, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
