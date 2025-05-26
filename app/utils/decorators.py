import time
from flask import jsonify, request
import jwt
from app.utils.database import get_db_connection
from app.config import SECRET_KEY
from functools import wraps

def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            conn.close()
            if not token_data:
                return jsonify({"error": "Invalid or expired token"}), 401
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            print(f"Error in require_token: {e}")
            return jsonify({"error": "Internal server error"}), 500
        return f(token, *args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            # Проверяем токен
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            username = payload["username"]
            
            # Проверяем, что токен действителен
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            if not cursor.fetchone():
                conn.close()
                return jsonify({"error": "Invalid or expired token"}), 401
            
            # Проверяем, что пользователь является администратором
            cursor.execute("""
                SELECT r.code 
                FROM Roles r 
                JOIN UsersAndRoles ur ON r.id = ur.role_id 
                WHERE ur.user_id = ? AND r.code = 'admin' AND ur.deleted_at IS NULL
            """, (username,))
            
            if not cursor.fetchone():
                conn.close()
                return jsonify({"error": "Admin access required"}), 403
                
            conn.close()
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            print(f"Error in admin_required: {e}")
            return jsonify({"error": "Internal server error"}), 500
            
        return f(*args, **kwargs)
    return wrapper