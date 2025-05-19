from flask import Blueprint, request, jsonify
from app.controllers.user_role_controller import UserRoleController
from app.requests.user_role_requests import AssignRoleRequest
from app.utils.decorators import require_token

user_role_bp = Blueprint('user_role', __name__)
user_role_controller = UserRoleController()

@user_role_bp.route('/<user_id>/role', methods=['GET'], endpoint='get_user_roles')
@require_token
def get_user_roles(token, user_id):
    return user_role_controller.get_user_roles(user_id, token)

@user_role_bp.route('/<user_id>/role', methods=['POST'], endpoint='assign_role')
@require_token
def assign_role(token, user_id):
    data = request.get_json()
    req = AssignRoleRequest(user_id, data['role_id'], token)
    return user_role_controller.assign_role(req)

@user_role_bp.route('/<user_id>/role/<int:role_id>', methods=['DELETE'], endpoint='delete_user_role')
@require_token
def delete_user_role(token, user_id, role_id):
    return user_role_controller.delete_role(user_id, role_id, token)

@user_role_bp.route('/<user_id>/role/<int:role_id>/soft', methods=['DELETE'], endpoint='soft_delete_user_role')
@require_token
def soft_delete_user_role(token, user_id, role_id):
    return user_role_controller.soft_delete_role(user_id, role_id, token)

@user_role_bp.route('/<user_id>/role/<int:role_id>/restore', methods=['POST'], endpoint='restore_user_role')
@require_token
def restore_user_role(token, user_id, role_id):
    return user_role_controller.restore_role(user_id, role_id, token)