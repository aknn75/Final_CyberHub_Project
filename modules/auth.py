# modules/auth.py
import sqlite3
import hashlib
import os
from functools import wraps
from flask import session, redirect, url_for, flash

def init_db():
    """Initialize the users database if it doesn't exist"""
    conn = sqlite3.connect('data/users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash a password for storage"""
    salt = os.urandom(32)  # A new salt for this user
    key = hashlib.pbkdf2_hmac(
        'sha256',  # Hash digest algorithm
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Salt
        100000,  # 100,000 iterations of SHA-256
    )
    # Store salt and key
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt_hex, key_hex = stored_password.split(':')
    salt = bytes.fromhex(salt_hex)
    stored_key = bytes.fromhex(key_hex)
    # Use the same hash function
    key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000,
    )
    return key == stored_key

def register_user(username, email, password):
    """Register a new user"""
    hashed_password = hash_password(password)
    conn = sqlite3.connect('data/users.db')
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username or email already exists
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    """Authenticate a user"""
    conn = sqlite3.connect('data/users.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(user[2], password):
        return {'id': user[0], 'username': user[1]}
    return None

def login_required(f):
    """Decorator to require login for specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function