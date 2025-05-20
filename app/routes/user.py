from flask import Blueprint, request, jsonify
from app.controllers.user_controller import UserController
from app.requests.auth_requests import RegisterRequest
from app.utils.decorators import require_token
from app.controllers.changelog_controller import ChangeLogController

user_bp = Blueprint('user', __name__)
user_controller = UserController()
changelog_controller = ChangeLogController()

@user_bp.route('/', methods=['GET'], endpoint='get_users')
@require_token
def get_users(token):
    return user_controller.get_list(token)

@user_bp.route('/<username>', methods=['PUT'], endpoint='update_user')
@require_token
def update_user(token, username):
    data = request.get_json()
    return user_controller.update(username, token, data)

@user_bp.route('/<username>', methods=['DELETE'], endpoint='delete_user')
@require_token
def delete_user(token, username):
    return user_controller.delete(username, token)

@user_bp.route('/<user_id>/story', methods=['GET'], endpoint='get_user_history')
@require_token
def get_user_history(token, user_id):
    return changelog_controller.get_user_history(user_id, token)