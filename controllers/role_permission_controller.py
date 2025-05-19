from flask import jsonify
from app.utils.database import get_db_connection
from app.requests.role_permission_requests import AssignPermissionRequest
from .role_controller import RoleController
from datetime import datetime

class RolePermissionController:
    def assign_permission(self, req: AssignPermissionRequest):
        if not RoleController._check_permission(req.token, "create-permission"):
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
        if not RoleController._check_permission(token, "delete-permission"):
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