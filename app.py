from flask import Flask, request, jsonify
import hashlib
import time
import os
import re
from datetime import datetime
import jwt
import sqlite3

app = Flask(__name__)

# Конфигурация
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', 5))
TOKEN_LIFETIME = int(os.environ.get('TOKEN_LIFETIME', 3600))

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Модель User
class User:
    def __init__(self, username, email, password_hash, birthday, created_at):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.birthday = birthday
        self.created_at = created_at

    def roles(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.* FROM Roles r
            JOIN UsersAndRoles ur ON r.id = ur.role_id
            WHERE ur.user_id = ? AND ur.deleted_at IS NULL AND r.deleted_at IS NULL
        ''', (self.username,))
        roles = [Role(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return roles

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        return User(**dict(row)) if row else None

# Модель Role
class Role:
    def __init__(self, id, name, description, code, created_at, created_by, deleted_at=None, deleted_by=None):
        self.id = id
        self.name = name
        self.description = description
        self.code = code
        self.created_at = created_at
        self.created_by = created_by
        self.deleted_at = deleted_at
        self.deleted_by = deleted_by

    def permissions(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.* FROM Permissions p
            JOIN RolesAndPermissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ? AND rp.deleted_at IS NULL AND p.deleted_at IS NULL
        ''', (self.id,))
        perms = [Permission(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return perms

# Модель Permission
class Permission:
    def __init__(self, id, name, description, code, created_at, created_by, deleted_at=None, deleted_by=None):
        self.id = id
        self.name = name
        self.description = description
        self.code = code
        self.created_at = created_at
        self.created_by = created_by
        self.deleted_at = deleted_at
        self.deleted_by = deleted_by

# DTO классы
class UserDTO:
    def __init__(self, user):
        self.username = user.username
        self.email = user.email
        self.birthday = user.birthday
        self.roles = [RoleDTO(role).to_dict() for role in user.roles()]

    def to_dict(self):
        return self.__dict__

class RoleDTO:
    def __init__(self, role):
        self.id = role.id
        self.name = role.name
        self.description = role.description
        self.code = role.code
        self.permissions = [PermissionDTO(perm).to_dict() for perm in role.permissions()]

    def to_dict(self):
        return self.__dict__

class RoleCollectionDTO:
    def __init__(self, roles):
        self.roles = [RoleDTO(role).to_dict() for role in roles]

    def to_dict(self):
        return {"roles": self.roles}

class PermissionDTO:
    def __init__(self, perm):
        self.id = perm.id
        self.name = perm.name
        self.description = perm.description
        self.code = perm.code

    def to_dict(self):
        return self.__dict__

class PermissionCollectionDTO:
    def __init__(self, perms):
        self.permissions = [PermissionDTO(perm).to_dict() for perm in perms]

    def to_dict(self):
        return {"permissions": self.permissions}

# Валидация
def validate_username(username): return re.match(r'^[A-Z][a-zA-Z]{6,}$', username) is not None
def validate_password(password): return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]', password) and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password)
def validate_email(email): return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) is not None
def validate_birthday(birthday_str):
    try:
        birth_date = datetime.strptime(birthday_str, '%Y-%m-%d')
        today = datetime.now()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age >= 14
    except ValueError:
        return False

# Классы запросов для авторизации
class LoginRequest:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def validate(self):
        if not validate_username(self.username): return {"error": "Invalid username format"}, 400
        if not validate_password(self.password): return {"error": "Invalid password format"}, 400
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
        if not validate_username(self.username): return {"error": "Invalid username format"}, 400
        if not validate_email(self.email): return {"error": "Invalid email format"}, 400
        if not validate_password(self.password): return {"error": "Invalid password format"}, 400
        if self.password != self.c_password: return {"error": "Passwords do not match"}, 400
        if not validate_birthday(self.birthday): return {"error": "Invalid birthday or age < 14"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM Users WHERE username = ? OR email = ?", (self.username.lower(), self.email))
        if cursor.fetchone():
            conn.close()
            return {"error": "Username or email already taken"}, 400
        conn.close()
        return None

    def to_resource(self):
        hashed_password = hashlib.sha256(self.password.encode()).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO Users (username, email, password_hash, birthday) VALUES (?, ?, ?, ?)',
                       (self.username.lower(), self.email, hashed_password, self.birthday))
        conn.commit()
        conn.close()
        return {"username": self.username}

# Классы запросов для Role
class CreateRoleRequest:
    def __init__(self, name, description, code, token):
        self.name = name
        self.description = description
        self.code = code
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        if not self.name or not self.code: return {"error": "Name and code are required"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Roles WHERE name = ? OR code = ?", (self.name, self.code))
        if cursor.fetchone():
            conn.close()
            return {"error": "Name or code already exists"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO Roles (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
                       (self.name, self.description, self.code, datetime.now().isoformat(), self.created_by))
        role_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return Role(role_id, self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)

class UpdateRoleRequest:
    def __init__(self, role_id, name, description, code, token):
        self.role_id = role_id
        self.name = name
        self.description = description
        self.code = code
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        if not self.name or not self.code: return {"error": "Name and code are required"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Roles WHERE (name = ? OR code = ?) AND id != ?", (self.name, self.code, self.role_id))
        if cursor.fetchone():
            conn.close()
            return {"error": "Name or code already exists"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Roles SET name = ?, description = ?, code = ? WHERE id = ?',
                       (self.name, self.description, self.code, self.role_id))
        conn.commit()
        cursor.execute("SELECT * FROM Roles WHERE id = ?", (self.role_id,))
        role = Role(**dict(cursor.fetchone()))
        conn.close()
        return role

# Классы запросов для Permission
class CreatePermissionRequest:
    def __init__(self, name, description, code, token):
        self.name = name
        self.description = description
        self.code = code
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        if not self.name or not self.code: return {"error": "Name and code are required"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Permissions WHERE name = ? OR code = ?", (self.name, self.code))
        if cursor.fetchone():
            conn.close()
            return {"error": "Name or code already exists"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO Permissions (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
                       (self.name, self.description, self.code, datetime.now().isoformat(), self.created_by))
        perm_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return Permission(perm_id, self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)

class UpdatePermissionRequest:
    def __init__(self, perm_id, name, description, code, token):
        self.perm_id = perm_id
        self.name = name
        self.description = description
        self.code = code
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        if not self.name or not self.code: return {"error": "Name and code are required"}, 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM Permissions WHERE (name = ? OR code = ?) AND id != ?", (self.name, self.code, self.perm_id))
        if cursor.fetchone():
            conn.close()
            return {"error": "Name or code already exists"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Permissions SET name = ?, description = ?, code = ? WHERE id = ?',
                       (self.name, self.description, self.code, self.perm_id))
        conn.commit()
        cursor.execute("SELECT * FROM Permissions WHERE id = ?", (self.perm_id,))
        perm = Permission(**dict(cursor.fetchone()))
        conn.close()
        return perm

# Классы запросов для UsersAndRoles
class AssignRoleRequest:
    def __init__(self, user_id, role_id, token):
        self.user_id = user_id
        self.role_id = role_id
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM UsersAndRoles WHERE user_id = ? AND role_id = ? AND deleted_at IS NULL", (self.user_id, self.role_id))
        if cursor.fetchone():
            conn.close()
            return {"error": "Role already assigned to user"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO UsersAndRoles (user_id, role_id, created_at, created_by) VALUES (?, ?, ?, ?)',
                       (self.user_id, self.role_id, datetime.now().isoformat(), self.created_by))
        conn.commit()
        conn.close()
        return {"user_id": self.user_id, "role_id": self.role_id}

# Классы запросов для RolesAndPermissions
class AssignPermissionRequest:
    def __init__(self, role_id, perm_id, token):
        self.role_id = role_id
        self.perm_id = perm_id
        self.token = token

    def validate(self):
        try:
            payload = jwt.decode(self.token, SECRET_KEY, algorithms=["HS256"])
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (self.token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return {"error": "Invalid or expired token"}, 401
            self.created_by = payload["username"]
            conn.close()
        except jwt.InvalidTokenError:
            return {"error": "Invalid token"}, 401
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM RolesAndPermissions WHERE role_id = ? AND permission_id = ? AND deleted_at IS NULL", (self.role_id, self.perm_id))
        if cursor.fetchone():
            conn.close()
            return {"error": "Permission already assigned to role"}, 400
        conn.close()
        return None

    def to_resource(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
                       (self.role_id, self.perm_id, datetime.now().isoformat(), self.created_by))
        conn.commit()
        conn.close()
        return {"role_id": self.role_id, "perm_id": self.perm_id}

# Контроллер для Role
class RoleController:
    def get_list(self, token):
        if not self._check_permission(token, "get-list-role"): return jsonify({"error": "Permission 'get-list-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Roles WHERE deleted_at IS NULL")
        roles = [Role(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(RoleCollectionDTO(roles).to_dict()), 200

    def get_role(self, role_id, token):
        if not self._check_permission(token, "read-role"): return jsonify({"error": "Permission 'read-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Roles WHERE id = ? AND deleted_at IS NULL", (role_id,))
        row = cursor.fetchone()
        conn.close()
        if not row: return jsonify({"error": "Role not found"}), 404
        return jsonify(RoleDTO(Role(**dict(row))).to_dict()), 200

    def create(self, req: CreateRoleRequest):
        if not self._check_permission(req.token, "create-role"): return jsonify({"error": "Permission 'create-role' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        role = req.to_resource()
        return jsonify(RoleDTO(role).to_dict()), 201

    def update(self, req: UpdateRoleRequest):
        if not self._check_permission(req.token, "update-role"): return jsonify({"error": "Permission 'update-role' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        role = req.to_resource()
        return jsonify(RoleDTO(role).to_dict()), 200

    def delete(self, role_id, token):
        if not self._check_permission(token, "delete-role"): return jsonify({"error": "Permission 'delete-role求required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Roles WHERE id = ?", (role_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role deleted"}), 200

    def soft_delete(self, role_id, token):
        if not self._check_permission(token, "delete-role"): return jsonify({"error": "Permission 'delete-role' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Roles SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL',
                       (datetime.now().isoformat(), payload["username"], role_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role soft deleted"}), 200

    def restore(self, role_id, token):
        if not self._check_permission(token, "restore-role"): return jsonify({"error": "Permission 'restore-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Roles SET deleted_at = NULL, deleted_by = NULL WHERE id = ?', (role_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role restored"}), 200

    def _check_permission(self, token, permission_code):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            if not token_data:
                return False
            username = token_data["username"]
            user = User.get_by_username(username)
            if not user:
                return False
            for role in user.roles():
                for perm in role.permissions():
                    if perm.code == permission_code:
                        return True
            return False
        except Exception as e:
            print(f"Error in _check_permission: {e}")
            return False

# Контроллер для Permission
class PermissionController:
    def get_list(self, token):
        if not self._check_permission(token, "get-list-permission"): return jsonify({"error": "Permission 'get-list-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Permissions WHERE deleted_at IS NULL")
        perms = [Permission(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(PermissionCollectionDTO(perms).to_dict()), 200

    def get_permission(self, perm_id, token):
        if not self._check_permission(token, "read-permission"): return jsonify({"error": "Permission 'read-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Permissions WHERE id = ? AND deleted_at IS NULL", (perm_id,))
        row = cursor.fetchone()
        conn.close()
        if not row: return jsonify({"error": "Permission not found"}), 404
        return jsonify(PermissionDTO(Permission(**dict(row))).to_dict()), 200

    def create(self, req: CreatePermissionRequest):
        if not self._check_permission(req.token, "create-permission"): return jsonify({"error": "Permission 'create-permission' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        perm = req.to_resource()
        return jsonify(PermissionDTO(perm).to_dict()), 201

    def update(self, req: UpdatePermissionRequest):
        if not self._check_permission(req.token, "update-permission"): return jsonify({"error": "Permission 'update-permission' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        perm = req.to_resource()
        return jsonify(PermissionDTO(perm).to_dict()), 200

    def delete(self, perm_id, token):
        if not self._check_permission(token, "delete-permission"): return jsonify({"error": "Permission 'delete-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Permissions WHERE id = ?", (perm_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Permission deleted"}), 200

    def soft_delete(self, perm_id, token):
        if not self._check_permission(token, "delete-permission"): return jsonify({"error": "Permission 'delete-permission' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Permissions SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL',
                       (datetime.now().isoformat(), payload["username"], perm_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Permission soft deleted"}), 200

    def restore(self, perm_id, token):
        if not self._check_permission(token, "restore-permission"): return jsonify({"error": "Permission 'restore-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE Permissions SET deleted_at = NULL, deleted_by = NULL WHERE id = ?', (perm_id,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Permission restored"}), 200

    _check_permission = RoleController._check_permission

# Контроллер для UsersAndRoles
class UserRoleController:
    def get_user_roles(self, user_id, token):
        if not self._check_permission(token, "get-list-role"): return jsonify({"error": "Permission 'get-list-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.* FROM Roles r
            JOIN UsersAndRoles ur ON r.id = ur.role_id
            WHERE ur.user_id = ? AND ur.deleted_at IS NULL AND r.deleted_at IS NULL
        ''', (user_id,))
        roles = [Role(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(RoleCollectionDTO(roles).to_dict()), 200

    def assign_role(self, req: AssignRoleRequest):
        if not self._check_permission(req.token, "create-role"): return jsonify({"error": "Permission 'create-role' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        result = req.to_resource()
        return jsonify(result), 201

    def delete_role(self, user_id, role_id, token):
        if not self._check_permission(token, "delete-role"): return jsonify({"error": "Permission 'delete-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM UsersAndRoles WHERE user_id = ? AND role_id = ?", (user_id, role_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role removed from user"}), 200

    def soft_delete_role(self, user_id, role_id, token):
        if not self._check_permission(token, "delete-role"): return jsonify({"error": "Permission 'delete-role' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE UsersAndRoles SET deleted_at = ?, deleted_by = ? WHERE user_id = ? AND role_id = ? AND deleted_at IS NULL',
                       (datetime.now().isoformat(), payload["username"], user_id, role_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role soft removed from user"}), 200

    def restore_role(self, user_id, role_id, token):
        if not self._check_permission(token, "restore-role"): return jsonify({"error": "Permission 'restore-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE UsersAndRoles SET deleted_at = NULL, deleted_by = NULL WHERE user_id = ? AND role_id = ?', (user_id, role_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Role restored for user"}), 200

    _check_permission = RoleController._check_permission

# Контроллер для RolesAndPermissions
class RolePermissionController:
    def assign_permission(self, req: AssignPermissionRequest):
        if not self._check_permission(req.token, "create-permission"): return jsonify({"error": "Permission 'create-permission' required"}), 403
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        result = req.to_resource()
        return jsonify(result), 201

    def delete_permission(self, role_id, perm_id, token):
        if not self._check_permission(token, "delete-permission"): return jsonify({"error": "Permission 'delete-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM RolesAndPermissions WHERE role_id = ? AND permission_id = ?", (role_id, perm_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Permission removed from role"}), 200

    _check_permission = RoleController._check_permission

# Контроллер для User
class UserController:
    def get_list(self, token):
        if not self._check_permission(token, "get-list-user"): return jsonify({"error": "Permission 'get-list-user' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users")
        users = [UserDTO(User(**row)).to_dict() for row in cursor.fetchall()]
        conn.close()
        return jsonify({"users": users}), 200

    _check_permission = RoleController._check_permission

# Контроллер авторизации
class AuthController:
    def register(self, req: RegisterRequest):
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        if "Authorization" in request.headers: return jsonify({"error": "Registration is only for unauthorized users"}), 403
        resource = req.to_resource()
        return jsonify(resource), 201

    def login(self, req: LoginRequest):
        validation = req.validate()
        if validation: return jsonify(validation[0]), validation[1]
        resource = req.to_resource()
        if "error" in resource: return jsonify(resource), resource.get("status", 401)
        return jsonify(resource), 200

    def get_current_user(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            conn.close()
            if not token_data: return jsonify({"error": "Invalid or expired token"}), 401
            user = User.get_by_username(token_data["username"])
            return jsonify(UserDTO(user).to_dict()), 200
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    def logout(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM Tokens WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return jsonify({"message": "Logged out"}), 200
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

# Декоратор
def require_token(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            conn.close()
            if not token_data:
                return jsonify({"error": "Invalid or expired token"}), 401
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            print(f"Error in require_token: {e}")
            return jsonify({"error": "Internal server error"}), 500
        return f(token, *args, **kwargs)
    return wrapper

# Инициализация контроллеров
auth_controller = AuthController()
role_controller = RoleController()
perm_controller = PermissionController()
user_role_controller = UserRoleController()
role_perm_controller = RolePermissionController()
user_controller = UserController()

# Маршруты авторизации
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    req = RegisterRequest(data['username'], data['email'], data['password'], data['c_password'], data['birthday'])
    return auth_controller.register(req)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    req = LoginRequest(data['username'], data['password'])
    return auth_controller.login(req)

@app.route('/api/auth/me', methods=['GET'], endpoint='get_me')
@require_token
def get_me(token):
    return auth_controller.get_current_user(token)

@app.route('/api/auth/out', methods=['POST'], endpoint='logout')
@require_token
def logout(token):
    return auth_controller.logout(token)

# Маршруты для Role
@app.route('/api/ref/policy/role', methods=['GET'], endpoint='get_roles')
@require_token
def get_roles(token):
    return role_controller.get_list(token)

@app.route('/api/ref/policy/role/<int:role_id>', methods=['GET'], endpoint='get_role')
@require_token
def get_role(token, role_id):
    return role_controller.get_role(role_id, token)

@app.route('/api/ref/policy/role', methods=['POST'], endpoint='create_role')
@require_token
def create_role(token):
    data = request.get_json()
    req = CreateRoleRequest(data['name'], data.get('description'), data['code'], token)
    return role_controller.create(req)

@app.route('/api/ref/policy/role/<int:role_id>', methods=['PUT'], endpoint='update_role')
@require_token
def update_role(token, role_id):
    data = request.get_json()
    req = UpdateRoleRequest(role_id, data['name'], data.get('description'), data['code'], token)
    return role_controller.update(req)

@app.route('/api/ref/policy/role/<int:role_id>', methods=['DELETE'], endpoint='delete_role')
@require_token
def delete_role(token, role_id):
    return role_controller.delete(role_id, token)

@app.route('/api/ref/policy/role/<int:role_id>/soft', methods=['DELETE'], endpoint='soft_delete_role')
@require_token
def soft_delete_role(token, role_id):
    return role_controller.soft_delete(role_id, token)

@app.route('/api/ref/policy/role/<int:role_id>/restore', methods=['POST'], endpoint='restore_role')
@require_token
def restore_role(token, role_id):
    return role_controller.restore(role_id, token)

# Маршруты для Permission
@app.route('/api/ref/policy/permission', methods=['GET'], endpoint='get_perms')
@require_token
def get_perms(token):
    return perm_controller.get_list(token)

@app.route('/api/ref/policy/permission/<int:perm_id>', methods=['GET'], endpoint='get_perm')
@require_token
def get_perm(token, perm_id):
    return perm_controller.get_permission(perm_id, token)

@app.route('/api/ref/policy/permission', methods=['POST'], endpoint='create_perm')
@require_token
def create_perm(token):
    data = request.get_json()
    req = CreatePermissionRequest(data['name'], data.get('description'), data['code'], token)
    return perm_controller.create(req)

@app.route('/api/ref/policy/permission/<int:perm_id>', methods=['PUT'], endpoint='update_perm')
@require_token
def update_perm(token, perm_id):
    data = request.get_json()
    req = UpdatePermissionRequest(perm_id, data['name'], data.get('description'), data['code'], token)
    return perm_controller.update(req)

@app.route('/api/ref/policy/permission/<int:perm_id>', methods=['DELETE'], endpoint='delete_perm')
@require_token
def delete_perm(token, perm_id):
    return perm_controller.delete(perm_id, token)

@app.route('/api/ref/policy/permission/<int:perm_id>/soft', methods=['DELETE'], endpoint='soft_delete_perm')
@require_token
def soft_delete_perm(token, perm_id):
    return perm_controller.soft_delete(perm_id, token)

@app.route('/api/ref/policy/permission/<int:perm_id>/restore', methods=['POST'], endpoint='restore_perm')
@require_token
def restore_perm(token, perm_id):
    return perm_controller.restore(perm_id, token)

# Маршруты для UsersAndRoles
@app.route('/api/ref/user/<user_id>/role', methods=['GET'], endpoint='get_user_roles')
@require_token
def get_user_roles(token, user_id):
    return user_role_controller.get_user_roles(user_id, token)

@app.route('/api/ref/user/<user_id>/role', methods=['POST'], endpoint='assign_role')
@require_token
def assign_role(token, user_id):
    data = request.get_json()
    req = AssignRoleRequest(user_id, data['role_id'], token)
    return user_role_controller.assign_role(req)

@app.route('/api/ref/user/<user_id>/role/<int:role_id>', methods=['DELETE'], endpoint='delete_user_role')
@require_token
def delete_user_role(token, user_id, role_id):
    return user_role_controller.delete_role(user_id, role_id, token)

@app.route('/api/ref/user/<user_id>/role/<int:role_id>/soft', methods=['DELETE'], endpoint='soft_delete_user_role')
@require_token
def soft_delete_user_role(token, user_id, role_id):
    return user_role_controller.soft_delete_role(user_id, role_id, token)

@app.route('/api/ref/user/<user_id>/role/<int:role_id>/restore', methods=['POST'], endpoint='restore_user_role')
@require_token
def restore_user_role(token, user_id, role_id):
    return user_role_controller.restore_role(user_id, role_id, token)

# Маршруты для RolesAndPermissions
@app.route('/api/ref/policy/role/<int:role_id>/permission', methods=['POST'], endpoint='assign_perm')
@require_token
def assign_perm(token, role_id):
    data = request.get_json()
    req = AssignPermissionRequest(role_id, data['perm_id'], token)
    return role_perm_controller.assign_permission(req)

@app.route('/api/ref/policy/role/<int:role_id>/permission/<int:perm_id>', methods=['DELETE'], endpoint='delete_role_perm')
@require_token
def delete_role_perm(token, role_id, perm_id):
    return role_perm_controller.delete_permission(role_id, perm_id, token)

# Маршруты для User
@app.route('/api/ref/user/', methods=['GET'], endpoint='get_users')
@require_token
def get_users(token):
    return user_controller.get_list(token)

if __name__ == '__main__':
    app.run(debug=True)