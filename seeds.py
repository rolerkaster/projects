from migrations import get_db_connection
from datetime import datetime
import hashlib

def seed_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Роли
    roles = [
        ("Admin", "Administrator role", "admin", "admin"),
        ("User", "Regular user role", "user", "admin"),
        ("Guest", "Guest role", "guest", "admin")
    ]
    cursor.executemany(
        'INSERT OR IGNORE INTO Roles (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
        [(r[0], r[1], r[2], datetime.now().isoformat(), r[3]) for r in roles]
    )

    # Разрешения
    entities = ["user", "role", "permission"]
    permissions = []
    for entity in entities:
        for action in ["get-list", "read", "create", "update", "delete", "restore"]:
            permissions.append((f"{action}-{entity}", f"{action} {entity}", f"{action}-{entity}", "admin"))
    cursor.executemany(
        'INSERT OR IGNORE INTO Permissions (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
        [(p[0], p[1], p[2], datetime.now().isoformat(), p[3]) for p in permissions]
    )

    # Связка ролей и разрешений
    cursor.execute("SELECT id, code FROM Roles")
    role_ids = {row["code"]: row["id"] for row in cursor.fetchall()}
    cursor.execute("SELECT id, code FROM Permissions")
    perm_ids = {row["code"]: row["id"] for row in cursor.fetchall()}

    # Admin: все разрешения
    admin_perms = [(role_ids["admin"], perm_id, datetime.now().isoformat(), "admin") for perm_id in perm_ids.values()]
    cursor.executemany(
        'INSERT OR IGNORE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
        admin_perms
    )

    # User: ограниченные разрешения
    user_perms = [
        (role_ids["user"], perm_ids["get-list-user"], datetime.now().isoformat(), "admin"),
        (role_ids["user"], perm_ids["read-user"], datetime.now().isoformat(), "admin"),
        (role_ids["user"], perm_ids["update-user"], datetime.now().isoformat(), "admin")
    ]
    cursor.executemany(
        'INSERT OR IGNORE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
        user_perms
    )

    # Guest: только список пользователей
    guest_perms = [(role_ids["guest"], perm_ids["get-list-user"], datetime.now().isoformat(), "admin")]
    cursor.executemany(
        'INSERT OR IGNORE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
        guest_perms
    )

    # Добавляем начального пользователя Adminuser
    cursor.execute(
        'INSERT OR IGNORE INTO Users (username, email, password_hash, birthday) VALUES (?, ?, ?, ?)',
        ("adminuser", "admin@example.com", hashlib.sha256("Admin123!".encode()).hexdigest(), "1990-01-01")
    )

    # Назначаем пользователю Adminuser роль Admin
    cursor.execute(
        'INSERT OR IGNORE INTO UsersAndRoles (user_id, role_id, created_at, created_by) VALUES (?, ?, ?, ?)',
        ("adminuser", role_ids["admin"], datetime.now().isoformat(), "admin")
    )

    conn.commit()
    conn.close()

if __name__ == '__main__':
    seed_data()