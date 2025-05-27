from flask import Blueprint
from app.controllers.report_controller import ReportController

report_bp = Blueprint('report', __name__)
controller = ReportController()

@report_bp.route('/generate', methods=['POST'])
def generate_report():
    """Endpoint для ручной генерации отчета"""
    return controller.generate_report() 