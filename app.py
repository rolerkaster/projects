from flask import Flask, request, jsonify
import hashlib
import time
import uuid
import os
import re
from datetime import datetime

app = Flask(__name__)

# Конфигурация
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', 5))
TOKEN_LIFETIME = int(os.environ.get('TOKEN_LIFETIME', 3600))

users = {}  # {username_lower: {"username": username, "password": hash, "email": email, "birthday": date, "tokens": {token: expiration}}}
tokens = {}  # {token: {"username": username, "expires": timestamp}}

# DTO классы
class UserResource:
    def __init__(self, username):
        self.username = username
    def to_dict(self):
        return {"username": self.username}

class LoginResource:
    def __init__(self, token):
        self.token = token
    def to_dict(self):
        return {"access_token": self.token}

class RegisterResource:
    def __init__(self, username):
        self.username = username
    def to_dict(self):
        return {"username": self.username}

# Валидация
def validate_username(username):
    if not re.match(r'^[A-Z][a-zA-Z]{6,}$', username):
        return False  # Только латинские буквы, начинается с большой, минимум 7 символов
    return True

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):  # Минимум 1 цифра
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Минимум 1 символ
        return False
    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password):  # Минимум 1 верхний и 1 нижний регистр
        return False
    return True

def validate_email(email):
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        return False
    return True

def validate_birthday(birthday_str):
    try:
        birth_date = datetime.strptime(birthday_str, '%Y-%m-%d')
        today = datetime.now()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age >= 14
    except ValueError:
        return False

# Классы запросов
class LoginRequest:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def validate(self):
        if not validate_username(self.username):
            return {"error": "Username must start with a capital letter, contain only Latin letters, and be at least 7 characters long"}, 400
        if not validate_password(self.password):
            return {"error": "Password must be at least 8 characters, with 1 digit, 1 symbol, and both upper/lowercase letters"}, 400
        return None

    def to_resource(self):
        token = str(uuid.uuid4())
        expires = time.time() + TOKEN_LIFETIME
        tokens[token] = {"username": self.username, "expires": expires}
        user = users[self.username.lower()]
        if "tokens" not in user:
            user["tokens"] = {}
        user["tokens"][token] = expires
        return LoginResource(token)

class RegisterRequest:
    def __init__(self, username, email, password, c_password, birthday):
        self.username = username
        self.email = email
        self.password = password
        self.c_password = c_password
        self.birthday = birthday

    def validate(self):
        # Валидация username
        if not validate_username(self.username):
            return {"error": "Username must start with a capital letter, contain only Latin letters, and be at least 7 characters long"}, 400
        if self.username.lower() in users:
            return {"error": "Username already taken"}, 400

        # Валидация email
        if not validate_email(self.email):
            return {"error": "Invalid email format"}, 400
        if any(user["email"] == self.email for user in users.values()):
            return {"error": "Email already taken"}, 400

        # Валидация password
        if not validate_password(self.password):
            return {"error": "Password must be at least 8 characters, with 1 digit, 1 symbol, and both upper/lowercase letters"}, 400
        if self.password != self.c_password:
            return {"error": "Passwords do not match"}, 400

        # Валидация birthday
        if not validate_birthday(self.birthday):
            return {"error": "Invalid date format or user must be at least 14 years old"}, 400

        return None

    def to_resource(self):
        hashed_password = hashlib.sha256(self.password.encode()).hexdigest()
        users[self.username.lower()] = {
            "username": self.username,
            "password": hashed_password,
            "email": self.email,
            "birthday": self.birthday
        }
        return RegisterResource(self.username)

# Контроллер
class AuthController:
    def register(self, req: RegisterRequest):
        validation_error = req.validate()
        if validation_error:
            return jsonify(validation_error[0]), validation_error[1]
        if "Authorization" in request.headers:
            return jsonify({"error": "Registration is only for unauthorized users"}), 403
        resource = req.to_resource()
        return jsonify(resource.to_dict()), 201

    def login(self, req: LoginRequest):
        validation_error = req.validate()
        if validation_error:
            return jsonify(validation_error[0]), validation_error[1]
        username_lower = req.username.lower()
        if username_lower not in users:
            return jsonify({"error": "User not found"}), 404
        hashed_password = hashlib.sha256(req.password.encode()).hexdigest()
        if users[username_lower]["password"] != hashed_password:
            return jsonify({"error": "Invalid password"}), 401
        if len(users[username_lower].get("tokens", {})) >= MAX_TOKENS:
            return jsonify({"error": "Max tokens exceeded"}), 403
        resource = req.to_resource()
        return jsonify(resource.to_dict()), 200

    def get_current_user(self, token):
        if token not in tokens or tokens[token]["expires"] < time.time():
            return jsonify({"error": "Invalid or expired token"}), 401
        username = tokens[token]["username"]
        return jsonify(UserResource(username).to_dict()), 200

    def logout(self, token):
        if token not in tokens:
            return jsonify({"error": "Invalid token"}), 401
        username = tokens[token]["username"]
        del tokens[token]
        del users[username.lower()]["tokens"][token]
        return jsonify({"message": "Logged out"}), 200

    def get_tokens(self, token):
        if token not in tokens or tokens[token]["expires"] < time.time():
            return jsonify({"error": "Invalid or expired token"}), 401
        username = tokens[token]["username"]
        user_tokens = users[username.lower()].get("tokens", {})
        return jsonify({"tokens": list(user_tokens.keys())}), 200

    def revoke_all_tokens(self, token):
        if token not in tokens or tokens[token]["expires"] < time.time():
            return jsonify({"error": "Invalid or expired token"}), 401
        username = tokens[token]["username"]
        for t in list(users[username.lower()].get("tokens", {})):
            del tokens[t]
        users[username.lower()]["tokens"] = {}
        return jsonify({"message": "All tokens revoked"}), 200

# Декоратор
def require_token(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token not in tokens or tokens[token]["expires"] < time.time():
            return jsonify({"error": "Unauthorized"}), 401
        return f(token, *args, **kwargs)
    return wrapper

controller = AuthController()

# Маршруты
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    req = RegisterRequest(data['username'], data['email'], data['password'], data['c_password'], data['birthday'])
    return controller.register(req)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    req = LoginRequest(data['username'], data['password'])
    return controller.login(req)

@app.route('/api/auth/me', methods=['GET'], endpoint='get_me')
@require_token
def get_me(token):
    return controller.get_current_user(token)

@app.route('/api/auth/out', methods=['POST'], endpoint='logout')
@require_token
def logout(token):
    return controller.logout(token)

@app.route('/api/auth/tokens', methods=['GET'], endpoint='get_tokens')
@require_token
def get_tokens(token):
    return controller.get_tokens(token)

@app.route('/api/auth/out_all', methods=['POST'], endpoint='revoke_all')
@require_token
def revoke_all(token):
    return controller.revoke_all_tokens(token)

if __name__ == '__main__':
    app.run(debug=True)