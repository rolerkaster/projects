from flask import Blueprint
from app.controllers.log_request_controller import LogRequestController
from app.utils.decorators import admin_required

log_request_routes = Blueprint('log_request_routes', __name__)


@log_request_routes.route('/api/ref/log/request', methods=['GET'])
@admin_required
def get_logs():
    return LogRequestController.get_logs()


@log_request_routes.route('/api/ref/log/request/<int:log_id>', methods=['GET'])
@admin_required
def get_log(log_id):
    return LogRequestController.get_log(log_id)


@log_request_routes.route('/api/ref/log/request/<int:log_id>', methods=['DELETE'])
@admin_required
def delete_log(log_id):
    return LogRequestController.delete_log(log_id) 