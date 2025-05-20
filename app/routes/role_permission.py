from flask import Blueprint, request, jsonify
from app.controllers.role_permission_controller import RolePermissionController
from app.requests.role_permission_requests import AssignPermissionRequest
from app.utils.decorators import require_token

role_perm_bp = Blueprint('role_permission', __name__)
role_perm_controller = RolePermissionController()

@role_perm_bp.route('/<int:role_id>/permission', methods=['POST'], endpoint='assign_perm')
@require_token
def assign_perm(token, role_id):
    data = request.get_json()
    req = AssignPermissionRequest(role_id, data['perm_id'], token)
    return role_perm_controller.assign_permission(req)

@role_perm_bp.route('/<int:role_id>/permission/<int:perm_id>', methods=['DELETE'], endpoint='delete_role_perm')
@require_token
def delete_role_perm(token, role_id, perm_id):
    return role_perm_controller.delete_permission(role_id, perm_id, token)