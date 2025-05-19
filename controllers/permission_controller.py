from flask import jsonify
from app.models.permission import Permission
from app.dtos.permission_dto import PermissionDTO, PermissionCollectionDTO
from app.utils.database import get_db_connection
from app.requests.permission_requests import CreatePermissionRequest, UpdatePermissionRequest
from .role_controller import RoleController
import jwt
from app.config import SECRET_KEY
from datetime import datetime
import json

class PermissionController:
    def get_list(self, token):
        if not RoleController._check_permission(token, "get-list-permission"):
            return jsonify({"error": "Permission 'get-list-permission' required"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Permissions WHERE deleted_at IS NULL")
        perms = [Permission(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return jsonify(PermissionCollectionDTO(perms).to_dict()), 200

    def get_permission(self, perm_id, token):
        if not RoleController._check_permission(token, "read-permission"):
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
        if not RoleController._check_permission(req.token, "create-permission"):
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
        if not RoleController._check_permission(req.token, "update-permission"):
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
        if not RoleController._check_permission(token, "delete-permission"):
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
        if not RoleController._check_permission(token, "delete-permission"):
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
        if not RoleController._check_permission(token, "restore-permission"):
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