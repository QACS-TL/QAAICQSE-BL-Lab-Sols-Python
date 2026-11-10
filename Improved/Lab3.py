import bcrypt
import secrets
import sqlite3
import jwt
import re
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
from contextlib import contextmanager
import time
import redis

@dataclass
class User:
    id: int
    email: str
    password_hash: str
    created_at: datetime
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class UserManager:
    def __init__(self, db_path: str, secret_key: str, redis_client: redis.Redis):
        self.db_path = db_path
        self.secret_key = secret_key  # Should be from environment variable
        self.redis_client = redis_client
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.token_expiry = timedelta(hours=1)
        self.reset_token_expiry = timedelta(minutes=15)
        
        # Initialize database with proper schema
        self._init_database()
        
    def _init_database(self):
        """Initialize database with secure schema"""
        with self._get_db_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    used BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
    @contextmanager
    def _get_db_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
        
    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
        
    def _hash_password(self, password: str) -> str:
        """Securely hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash with timing attack protection"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            # Always take roughly the same time even on error
            bcrypt.checkpw('dummy'.encode('utf-8'), bcrypt.gensalt())
            return False
            
    def _is_user_locked(self, user_row) -> bool:
        """Check if user account is locked"""
        if not user_row['locked_until']:
            return False
        locked_until = datetime.fromisoformat(user_row['locked_until'])
        return datetime.now() < locked_until
        
    def _check_rate_limit(self, identifier: str, max_attempts: int, window_seconds: int) -> bool:
        """Check rate limiting using Redis"""
        key = f"rate_limit:{identifier}"
        current_attempts = self.redis_client.get(key)
        
        if current_attempts is None:
            self.redis_client.setex(key, window_seconds, 1)
            return True
        
        if int(current_attempts) >= max_attempts:
            return False
            
        self.redis_client.incr(key)
        return True
        
    def register_user(self, email: str, password: str, personal_info: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new user with comprehensive validation"""
        # Input validation
        if not email or not isinstance(email, str):
            raise SecurityError("Invalid email")
        if not self._validate_email(email):
            raise SecurityError("Invalid email format")
        if not password or not isinstance(password, str):
            raise SecurityError("Invalid password")
        if not self._validate_password_strength(password):
            raise SecurityError("Password does not meet security requirements")
            
        # Rate limiting for registration
        if not self._check_rate_limit(f"register:{email}", 3, 3600):  # 3 attempts per hour
            raise SecurityError("Too many registration attempts")
            
        email = email.lower().strip()
        password_hash = self._hash_password(password)
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, password_hash)
                )
                user_id = cursor.lastrowid
                
            logging.info(f"User registered successfully: {email}")
            return {"user_id": user_id, "email": email, "message": "User registered successfully"}
            
        except sqlite3.IntegrityError:
            raise SecurityError("Email already exists")
            
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with security controls"""
        if not email or not password:
            time.sleep(0.5)  # Prevent timing attacks
            return None
            
        # Rate limiting for login attempts
        if not self._check_rate_limit(f"login:{email}", 10, 900):  # 10 attempts per 15 minutes
            raise SecurityError("Too many login attempts")
            
        email = email.lower().strip()
        
        with self._get_db_connection() as conn:
            user_row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            
            if not user_row:
                time.sleep(0.5)  # Prevent user enumeration
                return None
                
            # Check if account is locked
            if self._is_user_locked(user_row):
                raise SecurityError("Account is temporarily locked")
                
            # Verify password
            if not self._verify_password(password, user_row['password_hash']):
                # Increment failed attempts
                new_attempts = user_row['failed_login_attempts'] + 1
                locked_until = None
                
                if new_attempts >= self.max_login_attempts:
                    locked_until = datetime.now() + self.lockout_duration
                    
                conn.execute(
                    "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_attempts, locked_until, user_row['id'])
                )
                
                logging.warning(f"Failed login attempt for {email}. Attempts: {new_attempts}")
                return None
                
            # Successful login - reset failed attempts and update last login
            conn.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                (datetime.now(), user_row['id'])
            )
            
        # Generate JWT token
        payload = {
            'user_id': user_row['id'],
            'email': user_row['email'],
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        logging.info(f"Successful login for {email}")
        return {
            'token': token,
            'user': {
                'id': user_row['id'],
                'email': user_row['email'],
                'last_login': user_row['last_login']
            }
        }
        
    def generate_reset_token(self, email: str) -> str:
        """Generate secure password reset token"""
        if not self._validate_email(email):
            raise SecurityError("Invalid email")
            
        # Rate limiting for reset requests
        if not self._check_rate_limit(f"reset:{email}", 3, 3600):  # 3 resets per hour
            raise SecurityError("Too many reset attempts")
            
        email = email.lower().strip()
        
        with self._get_db_connection() as conn:
            user_row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            
            if not user_row:
                # Don't reveal if email exists
                logging.warning(f"Password reset requested for non-existent email: {email}")
                return "If the email exists, a reset link has been sent"
                
            # Generate cryptographically secure token
            reset_token = secrets.token_urlsafe(32)
            
            # Store token with expiration
            conn.execute(
                "INSERT INTO reset_tokens (token, user_id) VALUES (?, ?)",
                (reset_token, user_row['id'])
            )
            
        logging.info(f"Password reset token generated for {email}")
        return reset_token
        
    def reset_password(self, reset_token: str, new_password: str) -> Dict[str, str]:
        """Reset password using secure token"""
        if not reset_token or not new_password:
            raise SecurityError("Invalid reset request")
            
        if not self._validate_password_strength(new_password):
            raise SecurityError("Password does not meet security requirements")
            
        with self._get_db_connection() as conn:
            # Validate token
            token_row = conn.execute(
                """SELECT rt.user_id, rt.created_at, rt.used, u.email 
                   FROM reset_tokens rt 
                   JOIN users u ON rt.user_id = u.id 
                   WHERE rt.token = ?""",
                (reset_token,)
            ).fetchone()
            
            if not token_row:
                raise SecurityError("Invalid reset token")
                
            if token_row['used']:
                raise SecurityError("Reset token already used")
                
            # Check token expiration
            created_at = datetime.fromisoformat(token_row['created_at'])
            if datetime.now() - created_at > self.reset_token_expiry:
                raise SecurityError("Reset token expired")
                
            # Update password
            new_password_hash = self._hash_password(new_password)
            conn.execute(
                "UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                (new_password_hash, token_row['user_id'])
            )
            
            # Mark token as used
            conn.execute(
                "UPDATE reset_tokens SET used = TRUE WHERE token = ?",
                (reset_token,)
            )
            
        logging.info(f"Password reset successful for user {token_row['user_id']}")
        return {"message": "Password reset successful"}
        
    def get_user_data(self, user_id: int, requesting_user_id: int) -> Optional[Dict[str, Any]]:
        """Get user data with proper authorization"""
        # Authorization check - users can only access their own data
        if user_id != requesting_user_id:
            logging.warning(f"Unauthorized access attempt: user {requesting_user_id} tried to access user {user_id}")
            raise SecurityError("Unauthorized access")
            
        with self._get_db_connection() as conn:
            user_row = conn.execute(
                "SELECT id, email, created_at, last_login FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            
            if not user_row:
                return None
                
            return {
                'id': user_row['id'],
                'email': user_row['email'],
                'created_at': user_row['created_at'],
                'last_login': user_row['last_login']
            }
            
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user data"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise SecurityError("Token expired")
        except jwt.InvalidTokenError:
            raise SecurityError("Invalid token")