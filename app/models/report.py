from datetime import datetime

class Report:
    def __init__(self, report_type, data, generated_at=None):
        self.report_type = report_type
        self.data = data
        self.generated_at = generated_at or datetime.now()

    def to_dict(self):
        return {
            'report_type': self.report_type,
            'data': self.data,
            'generated_at': self.generated_at.isoformat()
        } 