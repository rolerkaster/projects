import hashlib
import time
import jwt
from app.utils.database import get_db_connection
from app.utils.validation import validate_username, validate_password, validate_email, validate_birthday
from app.config import SECRET_KEY, TOKEN_LIFETIME
import json
from datetime import datetime

class LoginRequest:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def validate(self):
        if not validate_username(self.username):
            return {"error": "Invalid username format"}, 400
        if not validate_password(self.password):
            return {"error": "Invalid password format"}, 400
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM Users WHERE username = ?", (self.username.lower(),))
        user = cursor.fetchone()
        if not user or user["password_hash"] != hashlib.sha256(self.password.encode()).hexdigest():
            conn.close()
            return {"error": "Invalid credentials"}, 401
        expires = int(time.time() + TOKEN_LIFETIME)
        token = jwt.encode({"username": self.username, "exp": expires}, SECRET_KEY, algorithm="HS256")
        cursor.execute('INSERT OR REPLACE INTO Tokens (token, username, expires) VALUES (?, ?, ?)',
                       (token, self.username.lower(), expires))
        conn.commit()
        conn.close()
        return {"access_token": token}

class RegisterRequest:
    def __init__(self, username, email, password, c_password, birthday):
        self.username = username
        self.email = email
        self.password = password
        self.c_password = c_password
        self.birthday = birthday

    def validate(self):
        if not validate_username(self.username):
            return {"error": "Invalid username format"}, 400
        if not validate_email(self.email):
            return {"error": "Invalid email format"}, 400
        if not validate_password(self.password):
            return {"error": "Invalid password format"}, 400
        if self.password != self.c_password:
            return {"error": "Passwords do not match"}, 400
        if not validate_birthday(self.birthday):
            return {"error": "Invalid birthday or age < 14"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM Users WHERE username = ? OR email = ?", (self.username.lower(), self.email))
        if cursor.fetchone():
            conn.close()
            return {"error": "Username or email already taken"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                hashed_password = hashlib.sha256(self.password.encode()).hexdigest()
                cursor.execute(
                    'INSERT INTO Users (username, email, password_hash, birthday) VALUES (?, ?, ?, ?)',
                    (self.username.lower(), self.email, hashed_password, self.birthday)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'user',
                        self.username.lower(),
                        json.dumps({}),
                        json.dumps({
                            "username": self.username.lower(),
                            "email": self.email,
                            "password_hash": hashed_password,
                            "birthday": self.birthday
                        }),
                        datetime.now().isoformat(),
                        self.username.lower()
                    )
                )
                conn.commit()
                return {"username": self.username}
        except Exception as e:
            conn.rollback()
            return {"error": str(e)}, 500
        finally:
            conn.close()