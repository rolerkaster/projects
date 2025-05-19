from app.utils.database import get_db_connection
from .role import Role

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