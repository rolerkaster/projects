from app.utils.database import get_db_connection
from .role import Role

class User:
    def __init__(self, username, email, password_hash, birthday, created_at, two_factor_enabled=0):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.birthday = birthday
        self.created_at = created_at
        self.two_factor_enabled = two_factor_enabled

    def roles(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT r.* FROM Roles r
                JOIN UsersAndRoles ur ON r.id = ur.role_id
                WHERE ur.user_id = ? AND ur.deleted_at IS NULL AND r.deleted_at IS NULL
            ''', (self.username,))
            roles = [Role(**dict(row)) for row in cursor.fetchall()]
            return roles
        finally:
            conn.close()

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return User(**dict(row)) if row else None
        finally:
            conn.close()