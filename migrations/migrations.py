import sqlite3
from datetime import datetime
from app.config import SECRET_KEY, TWO_FACTOR_CODE_TTL  

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def run_migrations():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Таблица Roles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            code TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL,
            deleted_at TIMESTAMP,
            deleted_by TEXT
        )
    ''')

    # Таблица Permissions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            code TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL,
            deleted_at TIMESTAMP,
            deleted_by TEXT
        )
    ''')

    # Таблица UsersAndRoles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS UsersAndRoles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            role_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL,
            deleted_at TIMESTAMP,
            deleted_by TEXT,
            FOREIGN KEY (role_id) REFERENCES Roles(id)
        )
    ''')

    # Таблица RolesAndPermissions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS RolesAndPermissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL,
            deleted_at TIMESTAMP,
            deleted_by TEXT,
            FOREIGN KEY (role_id) REFERENCES Roles(id),
            FOREIGN KEY (permission_id) REFERENCES Permissions(id)
        )
    ''')

    # Таблица Users (добавим two_factor_enabled)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            birthday TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute("PRAGMA table_info(Users);")
    columns = [col[1] for col in cursor.fetchall()]
    if 'two_factor_enabled' not in columns:
        cursor.execute("ALTER TABLE Users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0")

    # Таблица Tokens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires INTEGER NOT NULL
        )
    ''')

    # Таблица ChangeLogs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ChangeLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            before_change TEXT NOT NULL,
            after_change TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL
        )
    ''')

    # Таблица TwoFactorCodes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS TwoFactorCodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code TEXT NOT NULL,
            client_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            request_count INTEGER DEFAULT 0,
            global_request_count INTEGER DEFAULT 0,
            last_request_at INTEGER DEFAULT 0,
            FOREIGN KEY (username) REFERENCES Users(username)
        )
    """)

    conn.commit()
    conn.close()

