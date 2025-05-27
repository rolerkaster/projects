from flask import jsonify
from app.services.report_service import ReportService
import os

class ReportController:
    def __init__(self):
        self.report_service = ReportService()
        self.time_interval = int(os.getenv('REPORT_TIME_INTERVAL', 24))

    def generate_report(self):
        """
        Генерирует отчет о активности в системе
        """
        try:
            report = self.report_service.generate_report(self.time_interval)
            filepath = self.report_service.save_report(
                report,
                format=os.getenv('REPORT_FORMAT', 'json')
            )
            self.report_service.send_report(filepath)
            
            return jsonify({
                'status': 'success',
                'message': 'Report generated and sent successfully'
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500 