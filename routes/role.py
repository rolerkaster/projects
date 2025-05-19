from flask import Blueprint, request, jsonify
from app.controllers.role_controller import RoleController
from app.controllers.changelog_controller import ChangeLogController
from app.requests.role_requests import CreateRoleRequest, UpdateRoleRequest
from app.utils.decorators import require_token

role_bp = Blueprint('role', __name__)
role_controller = RoleController()
changelog_controller = ChangeLogController()

@role_bp.route('/', methods=['GET'], endpoint='get_roles')
@require_token
def get_roles(token):
    return role_controller.get_list(token)

@role_bp.route('/<int:role_id>', methods=['GET'], endpoint='get_role')
@require_token
def get_role(token, role_id):
    return role_controller.get_role(role_id, token)

@role_bp.route('/', methods=['POST'], endpoint='create_role')
@require_token
def create_role(token):
    data = request.get_json()
    req = CreateRoleRequest(data['name'], data.get('description'), data['code'], token)
    return role_controller.create(req)

@role_bp.route('/<int:role_id>', methods=['PUT'], endpoint='update_role')
@require_token
def update_role(token, role_id):
    data = request.get_json()
    req = UpdateRoleRequest(role_id, data['name'], data.get('description'), data['code'], token)
    return role_controller.update(req)

@role_bp.route('/<int:role_id>', methods=['DELETE'], endpoint='delete_role')
@require_token
def delete_role(token, role_id):
    return role_controller.delete(role_id, token)

@role_bp.route('/<int:role_id>/soft', methods=['DELETE'], endpoint='soft_delete_role')
@require_token
def soft_delete_role(token, role_id):
    return role_controller.soft_delete(role_id, token)

@role_bp.route('/<int:role_id>/restore', methods=['POST'], endpoint='restore_role')
@require_token
def restore_role(token, role_id):
    return role_controller.restore(role_id, token)

@role_bp.route('/<int:role_id>/story', methods=['GET'], endpoint='get_role_history')
@require_token
def get_role_history(token, role_id):
    return changelog_controller.get_role_history(role_id, token)