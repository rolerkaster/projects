import time
import random
import hashlib
import jwt
from flask import jsonify, request
from app.requests.auth_requests import RegisterRequest, LoginRequest
from app.dtos.user_dto import UserDTO
from app.models.user import User
from app.utils.database import get_db_connection
from app.config import SECRET_KEY, TWO_FACTOR_CODE_TTL

class AuthController:
    def register(self, req: RegisterRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        if "Authorization" in request.headers:
            return jsonify({"error": "Registration is only for unauthorized users"}), 403
        try:
            conn = get_db_connection()
            with conn:
                cursor = conn.cursor()
                password_hash = hashlib.sha256(req.password.encode()).hexdigest()
                cursor.execute(
                    "INSERT INTO Users (username, email, password_hash, birthday, two_factor_enabled, created_at) "
                    "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (req.username, req.email, password_hash, req.birthday, 0)
                )
                conn.commit()
            return jsonify({
                "message": "User registered",
                "username": req.username,
                "email": req.email,
                "birthday": req.birthday
            }), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def login(self, req: LoginRequest):
        validation = req.validate()
        if validation:
            return jsonify(validation[0]), validation[1]
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                password_hash = hashlib.sha256(req.password.encode()).hexdigest()
                cursor.execute(
                    "SELECT * FROM Users WHERE username = ? AND password_hash = ?",
                    (req.username, password_hash)
                )
                user = cursor.fetchone()
                if not user:
                    return jsonify({"error": "Invalid username or password"}), 401
                user = dict(user)
                if user['two_factor_enabled']:
                    temp_token = jwt.encode({
                        "username": req.username,
                        "exp": int(time.time()) + 600,
                        "type": "2fa_temp"
                    }, SECRET_KEY, algorithm="HS256")
                    return jsonify({"temp_token": temp_token, "message": "2FA code required"}), 200
                else:
                    token = jwt.encode({
                        "username": req.username,
                        "exp": int(time.time()) + 3600
                    }, SECRET_KEY, algorithm="HS256")
                    cursor.execute(
                        "INSERT INTO Tokens (token, username, expires) VALUES (?, ?, ?)",
                        (token, req.username, int(time.time()) + 3600)
                    )
                    conn.commit()
                    return jsonify({"access_token": token}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def get_current_user(self, token):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            username = payload['username']
            cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            user = User(**dict(user))
            return jsonify(UserDTO(user).to_dict()), 200
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

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
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def enable_2fa(self, token, password):
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                username = payload['username']
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                cursor.execute(
                    "SELECT * FROM Users WHERE username = ? AND password_hash = ?",
                    (username, password_hash)
                )
                user = cursor.fetchone()
                if not user:
                    return jsonify({"error": "Invalid password"}), 401
                cursor.execute(
                    "UPDATE Users SET two_factor_enabled = 1 WHERE username = ?",
                    (username,)
                )
                conn.commit()
                return jsonify({"message": "2FA enabled"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def disable_2fa(self, token, password, code, client_id):
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                username = payload['username']
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                cursor.execute(
                    "SELECT * FROM Users WHERE username = ? AND password_hash = ?",
                    (username, password_hash)
                )
                user = cursor.fetchone()
                if not user:
                    return jsonify({"error": "Invalid password"}), 401
                cursor.execute(
                    "SELECT * FROM TwoFactorCodes WHERE username = ? AND client_id = ? AND code = ? AND expires_at > ?",
                    (username, client_id, code, int(time.time()))
                )
                two_factor = cursor.fetchone()
                if not two_factor:
                    return jsonify({"error": "Invalid or expired 2FA code"}), 401
                cursor.execute(
                    "UPDATE Users SET two_factor_enabled = 0 WHERE username = ?",
                    (username,)
                )
                cursor.execute(
                    "DELETE FROM TwoFactorCodes WHERE username = ? AND client_id = ?",
                    (username, client_id)
                )
                conn.commit()
                return jsonify({"message": "2FA disabled"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def request_2fa_code(self, temp_token, client_id):
        try:
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=["HS256"])
            if payload.get('type') != '2fa_temp':
                return jsonify({"error": "Invalid token type"}), 401
            username = payload['username']
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid temporary token"}), 401
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM Users WHERE username = ? AND two_factor_enabled = 1",
                    (username,)
                )
                user = cursor.fetchone()
                if not user:
                    return jsonify({"error": "2FA not enabled or user not found"}), 403
                cursor.execute(
                    "SELECT * FROM TwoFactorCodes WHERE username = ? AND client_id = ?",
                    (username, client_id)
                )
                existing_code = cursor.fetchone()
                cursor.execute(
                    "SELECT SUM(global_request_count) as total FROM TwoFactorCodes WHERE username = ?",
                    (username,)
                )
                global_count_row = cursor.fetchone()
                global_request_count = global_count_row['total'] or 0
                request_count = existing_code['request_count'] + 1 if existing_code else 1
                last_request_at = existing_code['last_request_at'] if existing_code else 0
                current_time = int(time.time())
                if request_count > 3:
                    if current_time - last_request_at < 30:
                        time.sleep(30 - (current_time - last_request_at))
                if global_request_count >= 5:
                    if current_time - last_request_at < 50:
                        time.sleep(50 - (current_time - last_request_at))
                code = str(random.randint(100000, 999999))
                created_at = current_time
                expires_at = created_at + TWO_FACTOR_CODE_TTL
                if existing_code:
                    cursor.execute(
                        "UPDATE TwoFactorCodes SET code = ?, created_at = ?, expires_at = ?, request_count = ?, global_request_count = global_request_count + 1, last_request_at = ? "
                        "WHERE username = ? AND client_id = ?",
                        (code, created_at, expires_at, request_count, created_at, username, client_id)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO TwoFactorCodes (username, code, client_id, created_at, expires_at, request_count, global_request_count, last_request_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (username, code, client_id, created_at, expires_at, request_count, 1, created_at)
                    )
                conn.commit()
                print(f"2FA Code for {username} (client {client_id}): {code}")
                return jsonify({"message": "2FA code generated"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()

    def verify_2fa_code(self, temp_token, code, client_id):
        try:
            payload = jwt.decode(temp_token, SECRET_KEY, algorithms=["HS256"])
            if payload.get('type') != '2fa_temp':
                return jsonify({"error": "Invalid token type"}), 401
            username = payload['username']
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid temporary token"}), 401
        conn = get_db_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM TwoFactorCodes WHERE username = ? AND client_id = ? AND code = ? AND expires_at > ?",
                    (username, client_id, code, int(time.time()))
                )
                two_factor = cursor.fetchone()
                if not two_factor:
                    return jsonify({"error": "Invalid or expired 2FA code"}), 401
                cursor.execute(
                    "DELETE FROM TwoFactorCodes WHERE username = ? AND client_id = ?",
                    (username, client_id)
                )
                token = jwt.encode({
                    "username": username,
                    "exp": int(time.time()) + 3600
                }, SECRET_KEY, algorithm="HS256")
                cursor.execute(
                    "INSERT INTO Tokens (token, username, expires) VALUES (?, ?, ?)",
                    (token, username, int(time.time()) + 3600)
                )
                conn.commit()
                return jsonify({"access_token": token}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            conn.close()