#!/usr/bin/env python3
"""Encrypting passwords"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """function that expects one string argument name
       password and returns a salted, hashed password
    """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check valid password"""
    encoded = password.encode()
    return bcrypt.checkpw(encoded, hashed_password)
