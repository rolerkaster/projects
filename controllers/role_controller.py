from flask import jsonify
from app.models.role import Role
from app.dtos.role_dto import RoleDTO, RoleCollectionDTO
from app.utils.database import get_db_connection
from app.requests.role_requests import CreateRoleRequest, UpdateRoleRequest
from app.models.user import User
import jwt
from app.config import SECRET_KEY
from datetime import datetime
import time
import json

class RoleController:
    def get_list(self, token):
        if not RoleController._check_permission(token, "get-list-role"):
            return jsonify({"error": "Permission 'get-list-role' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Roles WHERE deleted_at IS NULL")
        roles = [Role(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(RoleCollectionDTO(roles).to_dict()), 200

    def get_role(self, role_id, token):
        if not RoleController._check_permission(token, "read-role"):
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
        if not RoleController._check_permission(req.token, "create-role"):
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
        if not RoleController._check_permission(req.token, "update-role"):
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
        if not RoleController._check_permission(token, "delete-role"):
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
        if not RoleController._check_permission(token, "delete-role"):
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
        if not RoleController._check_permission(token, "restore-role"):
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