import time
from flask import jsonify, request
import jwt
from app.utils.database import get_db_connection
from app.config import SECRET_KEY

def require_token(f):
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