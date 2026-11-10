import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta

import jwt


class UserManager:
    def __init__(self, database_path="users.db", secret_key=None):
        self.secret_key = secret_key or os.environ.get("JWT_SECRET_KEY")
        if not self.secret_key:
            raise ValueError("A JWT secret key must be configured")

        self.conn = sqlite3.connect(database_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                info TEXT NOT NULL
            )"""
        )
        self.conn.commit()

    @staticmethod
    def _hash_password(password, salt=None):
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
        encoded_salt = base64.urlsafe_b64encode(salt).decode()
        encoded_digest = base64.urlsafe_b64encode(digest).decode()
        return f"pbkdf2_sha256$310000${encoded_salt}${encoded_digest}"

    @classmethod
    def _verify_password(cls, password, stored_hash):
        try:
            algorithm, iterations, salt, expected = stored_hash.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            salt_bytes = base64.urlsafe_b64decode(salt.encode())
            actual = cls._hash_password_with_iterations(
                password, salt_bytes, int(iterations)
            )
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _hash_password_with_iterations(password, salt, iterations):
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return base64.urlsafe_b64encode(digest).decode()

    def _token(self, user_id, token_type, lifetime):
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "sub": str(user_id),
                "type": token_type,
                "iat": now,
                "exp": now + lifetime,
            },
            self.secret_key,
            algorithm="HS256",
        )

    def create_password_reset_token(self, email):
        user = self.conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user is None:
            return None
        return self._token(user["id"], "password_reset", timedelta(minutes=15))

    def register_user(self, email, password, personal_info):
        if not isinstance(email, str) or not email.strip() or "@" not in email:
            raise ValueError("A valid email is required")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not isinstance(personal_info, str):
            raise TypeError("Personal information must be a string")

        normalized_email = email.strip().lower()
        try:
            cursor = self.conn.execute(
                "INSERT INTO users (email, password, info) VALUES (?, ?, ?)",
                (normalized_email, self._hash_password(password), personal_info),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Email is already registered") from exc
        return {"id": cursor.lastrowid, "email": normalized_email}

    def authenticate_user(self, email, password):
        if not isinstance(email, str) or not isinstance(password, str):
            return None
        user = self.conn.execute(
            "SELECT id, email, password, info FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
        if user is None or not self._verify_password(password, user["password"]):
            return None

        return {
            "token": self._token(user["id"], "access", timedelta(hours=1)),
            "user": self._public_user(user),
        }

    def reset_password(self, email, new_password, reset_token):
        if not isinstance(new_password, str) or len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not isinstance(email, str) or not isinstance(reset_token, str):
            return False
        try:
            claims = jwt.decode(reset_token, self.secret_key, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return False

        user = self.conn.execute(
            "SELECT id FROM users WHERE email = ?", (email.strip().lower(),)
        ).fetchone()
        if (
            user is None
            or claims.get("type") != "password_reset"
            or claims.get("sub") != str(user["id"])
        ):
            return False

        self.conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (self._hash_password(new_password), user["id"]),
        )
        self.conn.commit()
        return True

    @staticmethod
    def _public_user(user):
        return {
            "id": user["id"],
            "email": user["email"],
            "personal_info": user["info"],
        }

    def get_user_data(self, user_id, requesting_user_id):
        if str(user_id) != str(requesting_user_id):
            return None
        user = self.conn.execute(
            "SELECT id, email, info FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return self._public_user(user) if user else None

    def close(self):
        self.conn.close()