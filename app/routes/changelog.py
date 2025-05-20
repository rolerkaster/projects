from flask import Blueprint, request, jsonify
from app.controllers.changelog_controller import ChangeLogController
from app.utils.decorators import require_token

changelog_bp = Blueprint('changelog', __name__)
changelog_controller = ChangeLogController()

@changelog_bp.route('/<int:log_id>/revert', methods=['POST'], endpoint='revert_mutation')
@require_token
def revert_mutation(token, log_id):
    return changelog_controller.revert_mutation(log_id, token)