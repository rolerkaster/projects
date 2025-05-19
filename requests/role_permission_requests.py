import jwt
from datetime import datetime, time
from app.utils.database import get_db_connection
from app.config import SECRET_KEY

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