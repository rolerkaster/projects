import sqlite3
from datetime import datetime

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

    # Таблица Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            birthday TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    ''')

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

    conn.commit()
    conn.close()

if __name__ == '__main__':
    run_migrations()