import os
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
from app.services.report_service import ReportService

logger = logging.getLogger(__name__)

class SchedulerService:
    def __init__(self):
        logger.info("Initializing SchedulerService")
        self.scheduler = BackgroundScheduler()
        self.report_service = ReportService()
        self.max_retries = int(os.getenv('REPORT_MAX_RETRIES', 3))
        self.timeout = int(os.getenv('REPORT_TIMEOUT', 1))
        self.time_interval = int(os.getenv('REPORT_TIME_INTERVAL', 24))
        self.report_format = os.getenv('REPORT_FORMAT', 'json')
        logger.info(f"SchedulerService initialized with: max_retries={self.max_retries}, timeout={self.timeout}, time_interval={self.time_interval}, format={self.report_format}")

    def generate_and_send_report(self):
        try:
            logger.info(f"Starting report generation at {datetime.now()}")
            
            # Генерация отчета
            report = self.report_service.generate_report(self.time_interval)
            logger.info("Report generated successfully")
            
            # Сохранение отчета в файл
            filepath = self.report_service.save_report(report, format=self.report_format)
            logger.info(f"Report saved to {filepath}")
            
            # Отправка отчета
            self.report_service.send_report(filepath)
            logger.info("Report sent successfully")
            
            logger.info(f"Report generation and sending completed at {datetime.now()}")
        except Exception as e:
            logger.error(f"Error in report generation: {str(e)}", exc_info=True)

    def start(self):
        """Запуск планировщика с настроенными параметрами"""
        try:
            # Добавляем задачу в планировщик
            self.scheduler.add_job(
                func=self.generate_and_send_report,
                trigger=IntervalTrigger(minutes=self.timeout),
                max_instances=1,
                coalesce=True,
                misfire_grace_time=None
            )
            
            # Запускаем планировщик
            self.scheduler.start()
            logger.info("Scheduler started successfully")
            
            # Запускаем первый отчет сразу
            self.generate_and_send_report()
        except Exception as e:
            logger.error(f"Error starting scheduler: {str(e)}", exc_info=True)

    def stop(self):
        """Остановка планировщика"""
        try:
            self.scheduler.shutdown()
            logger.info("Scheduler stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping scheduler: {str(e)}", exc_info=True) 