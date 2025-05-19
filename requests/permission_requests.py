import jwt
from datetime import datetime
import time
import json
from app.utils.database import get_db_connection
from app.config import SECRET_KEY
from app.models.permission import Permission

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
        if not self.name or not self.code:
            return {"error": "Name and code are required"}, 400
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
        if not self.name or not self.code:
            return {"error": "Name and code are required"}, 400
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
                    'UPDATE Permissions SET name = ?, description = ?, code = ? '
                    'WHERE id = ? AND (name != ? OR description != ? OR code != ?)',
                    (self.name, self.description, self.code, self.perm_id,
                    self.name, self.description, self.code)
                )
                
                if cursor.rowcount == 0:
                    cursor.execute("SELECT * FROM Permissions WHERE id = ?", (self.perm_id,))
                    perm = Permission(**dict(cursor.fetchone()))
                    return perm

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