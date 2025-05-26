from migrations.migrations import get_db_connection
from datetime import datetime
import hashlib

def seed_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Роли
        roles = [
            ("Admin", "Administrator role", "admin", "system"),
            ("User", "Regular user role", "user", "system"),
            ("Guest", "Guest role", "guest", "system")
        ]
        cursor.executemany(
            'INSERT OR REPLACE INTO Roles (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
            [(r[0], r[1], r[2], datetime.now().isoformat(), r[3]) for r in roles]
        )

        # Разрешения
        entities = ["user", "role", "permission", "log"]
        permissions = []
        for entity in entities:
            for action in ["get-list", "read", "create", "update", "delete", "restore", "get-story"]:
                permissions.append((f"{action}-{entity}", f"{action} {entity}", f"{action}-{entity}", "system"))
        cursor.executemany(
            'INSERT OR REPLACE INTO Permissions (name, description, code, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
            [(p[0], p[1], p[2], datetime.now().isoformat(), p[3]) for p in permissions]
        )

        # Получаем ID ролей и разрешений
        cursor.execute("SELECT id, code FROM Roles")
        role_ids = {row["code"]: row["id"] for row in cursor.fetchall()}
        cursor.execute("SELECT id, code FROM Permissions")
        perm_ids = {row["code"]: row["id"] for row in cursor.fetchall()}

        # Связка ролей и разрешений
        # Admin: все разрешения
        admin_perms = [(role_ids["admin"], perm_id, datetime.now().isoformat(), "system") for perm_id in perm_ids.values()]
        cursor.executemany(
            'INSERT OR REPLACE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
            admin_perms
        )

        # User: ограниченные разрешения
        user_perms = [
            (role_ids["user"], perm_ids["get-list-user"], datetime.now().isoformat(), "system"),
            (role_ids["user"], perm_ids["read-user"], datetime.now().isoformat(), "system"),
            (role_ids["user"], perm_ids["update-user"], datetime.now().isoformat(), "system")
        ]
        cursor.executemany(
            'INSERT OR REPLACE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
            user_perms
        )

        # Guest: только список пользователей
        guest_perms = [(role_ids["guest"], perm_ids["get-list-user"], datetime.now().isoformat(), "system")]
        cursor.executemany(
            'INSERT OR REPLACE INTO RolesAndPermissions (role_id, permission_id, created_at, created_by) VALUES (?, ?, ?, ?)',
            guest_perms
        )

        # Пользователь adminuser
        password_hash = hashlib.sha256("Admin123!".encode()).hexdigest()
        cursor.execute(
            'INSERT OR REPLACE INTO Users (username, email, password_hash, birthday, two_factor_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            ("Adminuser", "admin@example.com", password_hash, "1990-01-01", 0, datetime.now().isoformat())
        )

        # Привязка роли Admin к adminuser
        cursor.execute(
            'INSERT OR REPLACE INTO UsersAndRoles (user_id, role_id, created_at, created_by) VALUES (?, ?, ?, ?)',
            ("Adminuser", role_ids["admin"], datetime.now().isoformat(), "system")
        )

        conn.commit()
        print("Database seeded successfully!")
    except Exception as e:
        conn.rollback()
        print(f"Error seeding database: {str(e)}")
        raise  # Для отладки
    finally:
        conn.close()