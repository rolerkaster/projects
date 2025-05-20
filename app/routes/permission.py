from flask import Blueprint, request, jsonify
from app.controllers.permission_controller import PermissionController
from app.requests.permission_requests import CreatePermissionRequest, UpdatePermissionRequest
from app.utils.decorators import require_token
from app.controllers.changelog_controller import ChangeLogController

permission_bp = Blueprint('permission', __name__)
perm_controller = PermissionController()
changelog_controller = ChangeLogController()

@permission_bp.route('/', methods=['GET'], endpoint='get_perms')
@require_token
def get_perms(token):
    return perm_controller.get_list(token)

@permission_bp.route('/<int:perm_id>', methods=['GET'], endpoint='get_perm')
@require_token
def get_perm(token, perm_id):
    return perm_controller.get_permission(perm_id, token)

@permission_bp.route('/', methods=['POST'], endpoint='create_perm')
@require_token
def create_perm(token):
    data = request.get_json()
    req = CreatePermissionRequest(data['name'], data.get('description'), data['code'], token)
    return perm_controller.create(req)

@permission_bp.route('/<int:perm_id>', methods=['PUT'], endpoint='update_perm')
@require_token
def update_perm(token, perm_id):
    data = request.get_json()
    req = UpdatePermissionRequest(perm_id, data['name'], data.get('description'), data['code'], token)
    return perm_controller.update(req)

@permission_bp.route('/<int:perm_id>', methods=['DELETE'], endpoint='delete_perm')
@require_token
def delete_perm(token, perm_id):
    return perm_controller.delete(perm_id, token)

@permission_bp.route('/<int:perm_id>/soft', methods=['DELETE'], endpoint='soft_delete_perm')
@require_token
def soft_delete_perm(token, perm_id):
    return perm_controller.soft_delete(perm_id, token)

@permission_bp.route('/<int:perm_id>/restore', methods=['POST'], endpoint='restore_perm')
@require_token
def restore_perm(token, perm_id):
    return perm_controller.restore(perm_id, token)

@permission_bp.route('/<int:perm_id>/story', methods=['GET'], endpoint='get_permission_history')
@require_token
def get_permission_history(token, perm_id):
    return changelog_controller.get_permission_history(perm_id, token)