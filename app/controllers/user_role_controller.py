from flask import jsonify
from app.models.role import Role
from app.dtos.role_dto import RoleCollectionDTO
from app.utils.database import get_db_connection
from app.requests.user_role_requests import AssignRoleRequest
from .role_controller import RoleController
from datetime import datetime
import jwt
from app.config import SECRET_KEY

class UserRoleController:
    def get_user_roles(self, user_id, token):
        if not RoleController._check_permission(token, "get-list-role"):
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
        if not RoleController._check_permission(req.token, "create-role"):
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
        if not RoleController._check_permission(token, "delete-role"):
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
        if not RoleController._check_permission(token, "delete-role"):
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
        if not RoleController._check_permission(token, "restore-role"):
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