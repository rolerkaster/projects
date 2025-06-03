import sqlite3
from flask import request
import jwt
from app.config import SECRET_KEY
import logging

class Permission:
    def __init__(self, id, name, description, code, created_at, created_by, deleted_at=None, deleted_by=None):
        self.id = id
        self.name = name
        self.description = description
        self.code = code
        self.created_at = created_at
        self.created_by = created_by
        self.deleted_at = deleted_at
        self.deleted_by = deleted_by

    @staticmethod
    def check_permission(permission_name):
        logging.info(f"Checking permission: {permission_name}")
        
        # Получаем токен из заголовка
        auth_header = request.headers.get('Authorization', '')
        logging.info(f"Raw Authorization header: {auth_header}")
        
        if not auth_header:
            logging.warning("Authorization header is missing")
            return False
            
        if not auth_header.startswith('Bearer '):
            logging.warning("Authorization header does not start with 'Bearer '")
            return False
            
        token = auth_header.split(' ')[1]
        logging.info("Token extracted from header")
        
        try:
            # Декодируем токен
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = payload.get('username')
            logging.info(f"Token decoded, username: {current_user}")
            
            if not current_user:
                logging.warning("No username found in token")
                return False

            # Подключаемся к базе данных
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            try:
                # Проверяем наличие разрешения у пользователя через его роли
                query = '''
                    SELECT COUNT(*) FROM Permissions p
                    JOIN RolesAndPermissions rp ON p.id = rp.permission_id
                    JOIN UsersAndRoles ur ON rp.role_id = ur.role_id
                    WHERE p.name = ? AND ur.user_id = ?
                    AND p.deleted_at IS NULL
                    AND rp.deleted_at IS NULL
                    AND ur.deleted_at IS NULL
                '''
                logging.info(f"Executing query with params: {permission_name}, {current_user}")
                cursor.execute(query, (permission_name, current_user))

                count = cursor.fetchone()[0]
                logging.info(f"Permission check result: {count > 0}")
                return count > 0

            finally:
                conn.close()

        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid token error: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error in check_permission: {str(e)}")
            return False

        return False