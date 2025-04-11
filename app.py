from flask import Flask, request, jsonify
import hashlib
import time
import os
import re
from datetime import datetime
import jwt
import sqlite3
import json

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

# Модель ChangeLog
class ChangeLog:
    def __init__(self, id, entity_type, entity_id, before_change, after_change, created_at, created_by):
        self.id = id
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.before_change = before_change
        self.after_change = after_change
        self.created_at = created_at
        self.created_by = created_by

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

class ChangeLogDTO:
    def __init__(self, changelog):
        self.id = changelog.id
        self.entity_type = changelog.entity_type
        self.entity_id = changelog.entity_id
        before = json.loads(changelog.before_change)
        after = json.loads(changelog.after_change)
        self.changed_properties = {
            key: {"before": before.get(key), "after": after.get(key)}
            for key in after
            if before.get(key) != after.get(key) or key not in before
        }
        self.created_at = changelog.created_at
        self.created_by = changelog.created_by

    def to_dict(self):
        return self.__dict__

class ChangeLogCollectionDTO:
    def __init__(self, changelogs):
        self.changelogs = [ChangeLogDTO(log).to_dict() for log in changelogs]

    def to_dict(self):
        return {"changelogs": self.changelogs}

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
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                hashed_password = hashlib.sha256(self.password.encode()).hexdigest()
                cursor.execute(
                    'INSERT INTO Users (username, email, password_hash, birthday) VALUES (?, ?, ?, ?)',
                    (self.username.lower(), self.email, hashed_password, self.birthday)
                )
                # Логирование
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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO Roles (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
                    (self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)
                )
                role_id = cursor.lastrowid
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'role',
                        str(role_id),
                        json.dumps({}),
                        json.dumps({"name": self.name, "description": self.description, "code": self.code}),
                        datetime.now().isoformat(),
                        self.created_by
                    )
                )
                conn.commit()
                return Role(role_id, self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Roles WHERE id = ?", (self.role_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Roles SET name = ?, description = ?, code = ? WHERE id = ?',
                    (self.name, self.description, self.code, self.role_id)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'role',
                        str(self.role_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({"name": self.name, "description": self.description, "code": self.code}),
                        datetime.now().isoformat(),
                        self.created_by
                    )
                )
                conn.commit()
                cursor.execute("SELECT * FROM Roles WHERE id = ?", (self.role_id,))
                role = Role(**dict(cursor.fetchone()))
                return role
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO Permissions (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
                    (self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)
                )
                perm_id = cursor.lastrowid
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'permission',
                        str(perm_id),
                        json.dumps({}),
                        json.dumps({"name": self.name, "description": self.description, "code": self.code}),
                        datetime.now().isoformat(),
                        self.created_by
                    )
                )
                conn.commit()
                return Permission(perm_id, self.name, self.description, self.code, datetime.now().isoformat(), self.created_by)
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Permissions WHERE id = ?", (self.perm_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Permissions SET name = ?, description = ?, code = ? WHERE id = ?',
                    (self.name, self.description, self.code, self.perm_id)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'permission',
                        str(self.perm_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({"name": self.name, "description": self.description, "code": self.code}),
                        datetime.now().isoformat(),
                        self.created_by
                    )
                )
                conn.commit()
                cursor.execute("SELECT * FROM Permissions WHERE id = ?", (self.perm_id,))
                perm = Permission(**dict(cursor.fetchone()))
                return perm
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO UsersAndRoles (user_id, role_id, created_at, created_by) VALUES (?, ?, ?, ?)',
                    (self.user_id, self.role_id, datetime.now().isoformat(), self.created_by)
                )
                conn.commit()
                return {"user_id": self.user_id, "role_id": self.role_id}
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

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
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
                    (self.role_id, self.perm_id, datetime.now().isoformat(), self.created_by)
                )
                conn.commit()
                return {"role_id": self.role_id, "perm_id": self.perm_id}
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

# Контроллер для Role
class RoleController:
    def get_list(self, token):
        if not self._check_permission(token, "get-list-role"):
            return jsonify({"error": "Permission 'get-list-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Roles WHERE deleted_at IS NULL")
        roles = [Role(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(RoleCollectionDTO(roles).to_dict()), 200

    def get_role(self, role_id, token):
        if not self._check_permission(token, "read-role"):
            return jsonify({"error": "Permission 'read-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Roles WHERE id = ? AND deleted_at IS NULL", (role_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Role not found"}), 404
        return jsonify(RoleDTO(Role(**dict(row))).to_dict()), 200

    def create(self, req: CreateRoleRequest):
        if not self._check_permission(req.token, "create-role"):
            return jsonify({"error": "Permission 'create-role' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            role = req.to_resource()
            return jsonify(RoleDTO(role).to_dict()), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def update(self, req: UpdateRoleRequest):
        if not self._check_permission(req.token, "update-role"):
            return jsonify({"error": "Permission 'update-role' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            role = req.to_resource()
            return jsonify(RoleDTO(role).to_dict()), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def delete(self, role_id, token):
        if not self._check_permission(token, "delete-role"):
            return jsonify({"error": "Permission 'delete-role' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Roles WHERE id = ?", (role_id,))
                before = dict(cursor.fetchone())
                cursor.execute("DELETE FROM Roles WHERE id = ?", (role_id,))
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'role',
                        str(role_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({}),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Role deleted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def soft_delete(self, role_id, token):
        if not self._check_permission(token, "delete-role"):
            return jsonify({"error": "Permission 'delete-role' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Roles WHERE id = ?", (role_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Roles SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL',
                    (datetime.now().isoformat(), payload["username"], role_id)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'role',
                        str(role_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"],
                            "deleted_at": datetime.now().isoformat()
                        }),
                        datetime.now().isoformat(),
                        payload["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Role soft deleted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def restore(self, role_id, token):
        if not self._check_permission(token, "restore-role"):
            return jsonify({"error": "Permission 'restore-role' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Roles WHERE id = ?", (role_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Roles SET deleted_at = NULL, deleted_by = NULL WHERE id = ?',
                    (role_id,)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'role',
                        str(role_id),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"],
                            "deleted_at": before["deleted_at"]
                        }),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"]
                        }),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Role restored"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    @staticmethod
    def _check_permission(token, permission_code):
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
        if not self._check_permission(token, "get-list-permission"):
            return jsonify({"error": "Permission 'get-list-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Permissions WHERE deleted_at IS NULL")
        perms = [Permission(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(PermissionCollectionDTO(perms).to_dict()), 200

    def get_permission(self, perm_id, token):
        if not self._check_permission(token, "read-permission"):
            return jsonify({"error": "Permission 'read-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Permissions WHERE id = ? AND deleted_at IS NULL", (perm_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Permission not found"}), 404
        return jsonify(PermissionDTO(Permission(**dict(row))).to_dict()), 200

    def create(self, req: CreatePermissionRequest):
        if not self._check_permission(req.token, "create-permission"):
            return jsonify({"error": "Permission 'create-permission' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            perm = req.to_resource()
            return jsonify(PermissionDTO(perm).to_dict()), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def update(self, req: UpdatePermissionRequest):
        if not self._check_permission(req.token, "update-permission"):
            return jsonify({"error": "Permission 'update-permission' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            perm = req.to_resource()
            return jsonify(PermissionDTO(perm).to_dict()), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def delete(self, perm_id, token):
        if not self._check_permission(token, "delete-permission"):
            return jsonify({"error": "Permission 'delete-permission' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Permissions WHERE id = ?", (perm_id,))
                before = dict(cursor.fetchone())
                cursor.execute("DELETE FROM Permissions WHERE id = ?", (perm_id,))
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'permission',
                        str(perm_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({}),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Permission deleted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def soft_delete(self, perm_id, token):
        if not self._check_permission(token, "delete-permission"):
            return jsonify({"error": "Permission 'delete-permission' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Permissions WHERE id = ?", (perm_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Permissions SET deleted_at = ?, deleted_by = ? WHERE id = ? AND deleted_at IS NULL',
                    (datetime.now().isoformat(), payload["username"], perm_id)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'permission',
                        str(perm_id),
                        json.dumps({"name": before["name"], "description": before["description"], "code": before["code"]}),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"],
                            "deleted_at": datetime.now().isoformat()
                        }),
                        datetime.now().isoformat(),
                        payload["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Permission soft deleted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def restore(self, perm_id, token):
        if not self._check_permission(token, "restore-permission"):
            return jsonify({"error": "Permission 'restore-permission' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Permissions WHERE id = ?", (perm_id,))
                before = dict(cursor.fetchone())
                cursor.execute(
                    'UPDATE Permissions SET deleted_at = NULL, deleted_by = NULL WHERE id = ?',
                    (perm_id,)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'permission',
                        str(perm_id),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"],
                            "deleted_at": before["deleted_at"]
                        }),
                        json.dumps({
                            "name": before["name"],
                            "description": before["description"],
                            "code": before["code"]
                        }),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "Permission restored"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    _check_permission = RoleController._check_permission

# Контроллер для UsersAndRoles
class UserRoleController:
    def get_user_roles(self, user_id, token):
        if not self._check_permission(token, "get-list-role"):
            return jsonify({"error": "Permission 'get-list-role' required"}), 403
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
        if not self._check_permission(req.token, "create-role"):
            return jsonify({"error": "Permission 'create-role' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            result = req.to_resource()
            return jsonify(result), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def delete_role(self, user_id, role_id, token):
        if not self._check_permission(token, "delete-role"):
            return jsonify({"error": "Permission 'delete-role' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM UsersAndRoles WHERE user_id = ? AND role_id = ?", (user_id, role_id))
                conn.commit()
                return jsonify({"message": "Role removed from user"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def soft_delete_role(self, user_id, role_id, token):
        if not self._check_permission(token, "delete-role"):
            return jsonify({"error": "Permission 'delete-role' required"}), 403
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE UsersAndRoles SET deleted_at = ?, deleted_by = ? WHERE user_id = ? AND role_id = ? AND deleted_at IS NULL',
                    (datetime.now().isoformat(), payload["username"], user_id, role_id)
                )
                conn.commit()
                return jsonify({"message": "Role soft removed from user"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def restore_role(self, user_id, role_id, token):
        if not self._check_permission(token, "restore-role"):
            return jsonify({"error": "Permission 'restore-role' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE UsersAndRoles SET deleted_at = NULL, deleted_by = NULL WHERE user_id = ? AND role_id = ?',
                    (user_id, role_id)
                )
                conn.commit()
                return jsonify({"message": "Role restored for user"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    _check_permission = RoleController._check_permission

# Контроллер для RolesAndPermissions
class RolePermissionController:
    def assign_permission(self, req: AssignPermissionRequest):
        if not self._check_permission(req.token, "create-permission"):
            return jsonify({"error": "Permission 'create-permission' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            result = req.to_resource()
            return jsonify(result), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def delete_permission(self, role_id, perm_id, token):
        if not self._check_permission(token, "delete-permission"):
            return jsonify({"error": "Permission 'delete-permission' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM RolesAndPermissions WHERE role_id = ? AND permission_id = ?", (role_id, perm_id))
                conn.commit()
                return jsonify({"message": "Permission removed from role"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    _check_permission = RoleController._check_permission

# Контроллер для User
class UserController:
    def get_list(self, token):
        if not self._check_permission(token, "get-list-user"):
            return jsonify({"error": "Permission 'get-list-user' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users")
        users = [UserDTO(User(**row)).to_dict() for row in cursor.fetchall()]
        conn.close()
        return jsonify({"users": users}), 200

    def create(self, req: RegisterRequest):
        if not self._check_permission(req.token, "create-user"):
            return jsonify({"error": "Permission 'create-user' required"}), 403
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        try:
            result = req.to_resource()
            return jsonify(result), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def update(self, username, token, data):
        if not self._check_permission(token, "update-user"):
            return jsonify({"error": "Permission 'update-user' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
                before = dict(cursor.fetchone())
                if not before:
                    return jsonify({"error": "User not found"}), 404
                
                email = data.get('email', before['email'])
                password_hash = hashlib.sha256(data['password'].encode()).hexdigest() if data.get('password') else before['password_hash']
                birthday = data.get('birthday', before['birthday'])
                
                cursor.execute(
                    'UPDATE Users SET email = ?, password_hash = ?, birthday = ? WHERE username = ?',
                    (email, password_hash, birthday, username)
                )
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'user',
                        username,
                        json.dumps({
                            "username": before["username"],
                            "email": before["email"],
                            "password_hash": before["password_hash"],
                            "birthday": before["birthday"]
                        }),
                        json.dumps({
                            "username": username,
                            "email": email,
                            "password_hash": password_hash,
                            "birthday": birthday
                        }),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
                user = User(**dict(cursor.fetchone()))
                return jsonify(UserDTO(user).to_dict()), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def delete(self, username, token):
        if not self._check_permission(token, "delete-user"):
            return jsonify({"error": "Permission 'delete-user' required"}), 403
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
                before = dict(cursor.fetchone())
                if not before:
                    return jsonify({"error": "User not found"}), 404
                cursor.execute("DELETE FROM Users WHERE username = ?", (username,))
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        'user',
                        username,
                        json.dumps({
                            "username": before["username"],
                            "email": before["email"],
                            "password_hash": before["password_hash"],
                            "birthday": before["birthday"]
                        }),
                        json.dumps({}),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                conn.commit()
                return jsonify({"message": "User deleted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    _check_permission = RoleController._check_permission

# Контроллер для ChangeLog
class ChangeLogController:
    def get_user_history(self, user_id, token):
        if not RoleController._check_permission(token, "get-story-user"):
            return jsonify({"error": "Permission 'get-story-user' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ChangeLogs WHERE entity_type = 'user' AND entity_id = ?",
            (user_id,)
        )
        logs = [ChangeLog(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(ChangeLogCollectionDTO(logs).to_dict()), 200

    def get_role_history(self, role_id, token):
        if not RoleController._check_permission(token, "get-story-role"):
            return jsonify({"error": "Permission 'get-story-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ChangeLogs WHERE entity_type = 'role' AND entity_id = ?",
            (str(role_id),)
        )
        rows = cursor.fetchall()
        print("Fetched rows:", [dict(row) for row in rows])  # Отладочный вывод
        logs = [ChangeLog(**dict(row)) for row in rows]
        conn.close()
        return jsonify(ChangeLogCollectionDTO(logs).to_dict()), 200

    def get_permission_history(self, perm_id, token):
        if not RoleController._check_permission(token, "get-story-permission"):
            return jsonify({"error": "Permission 'get-story-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ChangeLogs WHERE entity_type = 'permission' AND entity_id = ?",
            (str(perm_id),)
        )
        logs = [ChangeLog(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(ChangeLogCollectionDTO(logs).to_dict()), 200

    def revert_mutation(self, log_id, token):
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM ChangeLogs WHERE id = ?", (log_id,))
                log = cursor.fetchone()
                if not log:
                    return jsonify({"error": "Log not found"}), 404
                
                entity_type = log["entity_type"]
                entity_id = log["entity_id"]
                before_change = json.loads(log["before_change"])

                if not RoleController._check_permission(token, f"update-{entity_type}"):
                    return jsonify({"error": f"Permission 'update-{entity_type}' required"}), 403

                if entity_type == "user":
                    cursor.execute(
                        'UPDATE Users SET username = ?, email = ?, password_hash = ?, birthday = ? WHERE username = ?',
                        (
                            before_change.get("username"),
                            before_change.get("email"),
                            before_change.get("password_hash"),
                            before_change.get("birthday"),
                            entity_id
                        )
                    )
                elif entity_type == "role":
                    cursor.execute(
                        'UPDATE Roles SET name = ?, description = ?, code = ? WHERE id = ?',
                        (
                            before_change.get("name"),
                            before_change.get("description"),
                            before_change.get("code"),
                            entity_id
                        )
                    )
                elif entity_type == "permission":
                    cursor.execute(
                        'UPDATE Permissions SET name = ?, description = ?, code = ? WHERE id = ?',
                        (
                            before_change.get("name"),
                            before_change.get("description"),
                            before_change.get("code"),
                            entity_id
                        )
                    )

                cursor.execute(
                    'SELECT * FROM {} WHERE {} = ?'.format(
                        entity_type.capitalize() + 's',
                        'username' if entity_type == 'user' else 'id'
                    ),
                    (entity_id,)
                )
                current_state = dict(cursor.fetchone())
                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        entity_type,
                        entity_id,
                        json.dumps(current_state),
                        json.dumps(before_change),
                        datetime.now().isoformat(),
                        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["username"]
                    )
                )
                
                conn.commit()
                return jsonify({"message": "Mutation reverted"}), 200
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

# Контроллер авторизации
class AuthController:
    def register(self, req: RegisterRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        if "Authorization" in request.headers:
            return jsonify({"error": "Registration is only for unauthorized users"}), 403
        try:
            resource = req.to_resource()
            return jsonify(resource), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def login(self, req: LoginRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        resource = req.to_resource()
        if "error" in resource:
            return jsonify(resource), resource.get("status", 401)
        return jsonify(resource), 200

    def get_current_user(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            conn.close()
            if not token_data:
                return jsonify({"error": "Invalid or expired token"}), 401
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
changelog_controller = ChangeLogController()

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

@app.route('/api/ref/policy/role/<int:role_id>/story', methods=['GET'], endpoint='get_role_history')
@require_token
def get_role_history(token, role_id):
    return changelog_controller.get_role_history(role_id, token)

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

@app.route('/api/ref/policy/permission/<int:perm_id>/story', methods=['GET'], endpoint='get_permission_history')
@require_token
def get_permission_history(token, perm_id):
    return changelog_controller.get_permission_history(perm_id, token)

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

@app.route('/api/ref/user/<username>', methods=['PUT'], endpoint='update_user')
@require_token
def update_user(token, username):
    data = request.get_json()
    return user_controller.update(username, token, data)

@app.route('/api/ref/user/<username>', methods=['DELETE'], endpoint='delete_user')
@require_token
def delete_user(token, username):
    return user_controller.delete(username, token)

@app.route('/api/ref/user/<user_id>/story', methods=['GET'], endpoint='get_user_history')
@require_token
def get_user_history(token, user_id):
    return changelog_controller.get_user_history(user_id, token)

# Маршрут для отката мутации
@app.route('/api/ref/changelog/<int:log_id>/revert', methods=['POST'], endpoint='revert_mutation')
@require_token
def revert_mutation(token, log_id):
    return changelog_controller.revert_mutation(log_id, token)

if __name__ == '__main__':
    app.run(debug=True)