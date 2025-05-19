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