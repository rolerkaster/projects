from app.utils.database import get_db_connection
from .permission import Permission

class Role:
    def __init__(self, id, name, description, code, created_at, created_by, deleted_at=None, deleted_by=None):
        self.id = id
        self.name = name
        self.description = description
        self.code = code
        self.created_at = created_at
        self.created_by = created_by
        self.deleted_at = deleted_at
        self.deleted_by = deleted_by

    def permissions(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.* FROM Permissions p
            JOIN RolesAndPermissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ? AND rp.deleted_at IS NULL AND p.deleted_at IS NULL
        ''', (self.id,))
        perms = [Permission(**dict(row)) for row in cursor.fetchall()]
        conn.close()
        return perms