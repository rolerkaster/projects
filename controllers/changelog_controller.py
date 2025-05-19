from flask import jsonify
from app.models.changelog import ChangeLog
from app.dtos.changelog_dto import ChangeLogCollectionDTO, ChangeLogDTO
from app.utils.database import get_db_connection
from app.models.user import User
from .role_controller import RoleController
import jwt
import json
from app.config import SECRET_KEY
from datetime import datetime

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
        logs = [ChangeLog(**dict(row)) for row in cursor.fetchall()]
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
                after_change = json.loads(log["after_change"])

                if not RoleController._check_permission(token, f"update-{entity_type}"):
                    return jsonify({"error": f"Permission 'update-{entity_type}' required"}), 403

                cursor.execute(
                    'SELECT * FROM {} WHERE {} = ?'.format(
                        entity_type.capitalize() + 's',
                        'username' if entity_type == 'user' else 'id'
                    ),
                    (entity_id,)
                )
                row = cursor.fetchone()
                current_state = dict(row) if row else {}

                exists = bool(row)
                changes_made = False

                if not exists and not after_change:
                    if entity_type == "user":
                        cursor.execute(
                            'INSERT INTO Users (username, email, password_hash, birthday) VALUES (?, ?, ?, ?)',
                            (
                                before_change.get("username", ""),
                                before_change.get("email", ""),
                                before_change.get("password_hash", ""),
                                before_change.get("birthday", "")
                            )
                        )
                    elif entity_type == "role":
                        cursor.execute(
                            'INSERT INTO Roles (id, name, description, code) VALUES (?, ?, ?, ?)',
                            (
                                entity_id,
                                before_change.get("name", ""),
                                before_change.get("description", ""),
                                before_change.get("code", "")
                            )
                        )
                    elif entity_type == "permission":
                        cursor.execute(
                            'INSERT INTO Permissions (id, name, description, code) VALUES (?, ?, ?, ?)',
                            (
                                entity_id,
                                before_change.get("name", ""),
                                before_change.get("description", ""),
                                before_change.get("code", "")
                            )
                        )
                    changes_made = True
                else:
                    if entity_type == "user":
                        cursor.execute(
                            'UPDATE Users SET username = ?, email = ?, password_hash = ?, birthday = ? '
                            'WHERE username = ?',
                            (
                                before_change.get("username", ""),
                                before_change.get("email", ""),
                                before_change.get("password_hash", ""),
                                before_change.get("birthday", ""),
                                entity_id
                            )
                        )
                        changes_made = cursor.rowcount > 0
                    elif entity_type == "role":
                        cursor.execute(
                            'UPDATE Roles SET name = ?, description = ?, code = ? '
                            'WHERE id = ?',
                            (
                                before_change.get("name", ""),
                                before_change.get("description", ""),
                                before_change.get("code", ""),
                                entity_id
                            )
                        )
                        changes_made = cursor.rowcount > 0
                    elif entity_type == "permission":
                        cursor.execute(
                            'UPDATE Permissions SET name = ?, description = ?, code = ? '
                            'WHERE id = ? AND (name != ? OR description != ? OR code != ?)',
                            (
                                before_change.get("name", ""),
                                before_change.get("description", ""),
                                before_change.get("code", ""),
                                entity_id,
                                before_change.get("name", ""),
                                before_change.get("description", ""),
                                before_change.get("code", "")
                            )
                        )
                        changes_made = cursor.rowcount > 0

                if not changes_made:
                    return jsonify({"message": "No changes to revert"}), 200

                reverted_state = before_change

                cursor.execute(
                    'INSERT INTO ChangeLogs (entity_type, entity_id, before_change, after_change, created_at, created_by) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        entity_type,
                        entity_id,
                        json.dumps(current_state),  
                        json.dumps(reverted_state),  
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