import hashlib
import sqlite3
import jwt
from datetime import datetime

class UserManager:
    def __init__(self):
        self.conn = sqlite3.connect('users.db')
        self.secret_key = "secret123"  # VULNERABLE: Hardcoded secret
        
    def register_user(self, email, password, personal_info):
        # VULNERABLE: No input validation, SQL injection possible
        hashed_password = hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: Weak hashing
        query = f"INSERT INTO users (email, password, info) VALUES ('{email}', '{hashed_password}', '{personal_info}')"
        self.conn.execute(query)
        return "User registered"
        
    def authenticate_user(self, email, password):
        # VULNERABLE: SQL injection, timing attack
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{hashed_password}'"
        result = self.conn.execute(query).fetchone()
        if result:
            token = jwt.encode({'email': email}, self.secret_key)  # VULNERABLE: No expiration
            return {'token': token, 'user': result}
        return None
        
    def reset_password(self, email, new_password, reset_token):
        # VULNERABLE: No token validation
        hashed_password = hashlib.md5(new_password.encode()).hexdigest()
        query = f"UPDATE users SET password = '{hashed_password}' WHERE email = '{email}'"
        self.conn.execute(query)
        return "Password reset"
        
    def get_user_data(self, user_id, requesting_user_id):
        # VULNERABLE: No authorization check
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return self.conn.execute(query).fetchone()