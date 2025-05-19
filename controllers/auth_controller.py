import time
from flask import jsonify, request
from app.requests.auth_requests import RegisterRequest, LoginRequest
from app.dtos.user_dto import UserDTO
from app.models.user import User
from app.utils.database import get_db_connection
import jwt

class AuthController:
    def register(self, req: RegisterRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        if "Authorization" in request.headers:
            return jsonify({"error": "Registration is only for unauthorized users"}), 403
        try:
            resource = req.to_resource()
            return jsonify(resource), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def login(self, req: LoginRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        resource = req.to_resource()
        if "error" in resource:
            return jsonify(resource), resource.get("status", 401)
        return jsonify(resource), 200

    def get_current_user(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM Tokens WHERE token = ? AND expires > ?", (token, int(time.time())))
            token_data = cursor.fetchone()
            conn.close()
            if not token_data:
                return jsonify({"error": "Invalid or expired token"}), 401
            user = User.get_by_username(token_data["username"])
            return jsonify(UserDTO(user).to_dict()), 200
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    def logout(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM Tokens WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return jsonify({"message": "Logged out"}), 200
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401