from flask import Blueprint, request, jsonify
from app.controllers.auth_controller import AuthController
from app.requests.auth_requests import RegisterRequest, LoginRequest
from app.utils.decorators import require_token

auth_bp = Blueprint('auth', __name__)
auth_controller = AuthController()

@auth_bp.route('/register', methods=['POST'], endpoint='register')
def register():
    data = request.get_json()
    req = RegisterRequest(data['username'], data['email'], data['password'], data['c_password'], data['birthday'])
    return auth_controller.register(req)

@auth_bp.route('/login', methods=['POST'], endpoint='login')
def login():
    data = request.get_json()
    req = LoginRequest(data['username'], data['password'])
    return auth_controller.login(req)

@auth_bp.route('/me', methods=['GET'], endpoint='get_current_user')
@require_token
def get_current_user(token):
    return auth_controller.get_current_user(token)

@auth_bp.route('/out', methods=['POST'], endpoint='logout')
@require_token
def logout(token):
    return auth_controller.logout(token)

@auth_bp.route('/2fa/enable', methods=['POST'], endpoint='enable_2fa')
@require_token
def enable_2fa(token):
    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({"error": "Password required"}), 400
    return auth_controller.enable_2fa(token, password)

@auth_bp.route('/2fa/disable', methods=['POST'], endpoint='disable_2fa')
@require_token
def disable_2fa(token):
    data = request.get_json()
    password = data.get('password')
    code = data.get('code')
    client_id = request.headers.get('User-Agent', request.remote_addr)
    if not password or not code:
        return jsonify({"error": "Password and code required"}), 400
    return auth_controller.disable_2fa(token, password, code, client_id)

@auth_bp.route('/2fa/code', methods=['POST'], endpoint='request_2fa_code')
def request_2fa_code():
    data = request.get_json()
    temp_token = data.get('temp_token')
    if not temp_token:
        return jsonify({"error": "Temporary token required"}), 401
    client_id = request.headers.get('User-Agent', request.remote_addr)
    return auth_controller.request_2fa_code(temp_token, client_id)

@auth_bp.route('/2fa/verify', methods=['POST'], endpoint='verify_2fa_code')
def verify_2fa_code():
    data = request.get_json()
    temp_token = data.get('temp_token')
    code = data.get('code')
    if not temp_token or not code:
        return jsonify({"error": "Temporary token and code required"}), 400
    client_id = request.headers.get('User-Agent', request.remote_addr)
    return auth_controller.verify_2fa_code(temp_token, code, client_id)