from flask import jsonify
from app.models.user import User
from app.dtos.user_dto import UserDTO
from app.utils.database import get_db_connection
from app.requests.auth_requests import RegisterRequest
from .role_controller import RoleController
import hashlib
import jwt
from app.config import SECRET_KEY
from datetime import datetime
import json

class UserController:
    def get_list(self, token):
        if not RoleController._check_permission(token, "get-list-user"):
            return jsonify({"error": "Permission 'get-list-user' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users")
        users = [UserDTO(User(**row)).to_dict() for row in cursor.fetchall()]
        conn.close()
        return jsonify({"users": users}), 200

    def create(self, req: RegisterRequest):
        if not RoleController._check_permission(req.token, "create-user"):
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
        if not RoleController._check_permission(token, "update-user"):
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
                password = data.get('password')
                password_hash = hashlib.sha256(password.encode()).hexdigest() if password else before['password_hash']
                birthday = data.get('birthday', before['birthday'])
                
                cursor.execute(
                    'UPDATE Users SET email = ?, password_hash = ?, birthday = ? '
                    'WHERE username = ? AND (email != ? OR password_hash != ? OR birthday != ?)',
                    (email, password_hash, birthday, username,
                    email, password_hash, birthday)
                )
                
                if cursor.rowcount == 0:
                    user = User(**before)
                    return jsonify(UserDTO(user).to_dict()), 200

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
        if not RoleController._check_permission(token, "delete-user"):
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