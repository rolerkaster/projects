import os
import time
from datetime import datetime
import threading
from app.controllers.report_controller import ReportController
from app.utils.logger import setup_logger

# Создаем директории
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# Настраиваем логгер
logger = setup_logger('ReportJob', 'report_job.log')

class ReportJob:
    _lock = threading.Lock()
    _is_running = False
    
    def __init__(self):
        self.max_execution_time = int(os.getenv('REPORT_MAX_EXECUTION_TIME', 30))  # в минутах
        self.timeout = int(os.getenv('REPORT_TIMEOUT', 60))  # в минутах
        self.max_retries = int(os.getenv('REPORT_MAX_RETRIES', 3))
        self.report_controller = ReportController()

    def run(self):
        """Запуск фоновой задачи"""
        # Проверяем, не выполняется ли уже задача
        if ReportJob._is_running:
            logger.warning("Report job is already running, skipping this execution")
            return False
        
        # Пытаемся захватить блокировку
        if not ReportJob._lock.acquire(blocking=False):
            logger.warning("Could not acquire lock, another instance is running")
            return False
        
        try:
            ReportJob._is_running = True
            logger.info("Starting report job")
            
            retries = 0
            while retries < self.max_retries:
                try:
                    start_time = datetime.utcnow()
                    
                    # Генерируем отчет
                    success = self.report_controller.generate_report()
                    
                    if success:
                        logger.info("Report job completed successfully")
                        return True
                    
                    # Проверяем, не превышено ли максимальное время выполнения
                    elapsed_minutes = (datetime.utcnow() - start_time).total_seconds() / 60
                    if elapsed_minutes >= self.max_execution_time:
                        logger.error(f"Report job exceeded maximum execution time of {self.max_execution_time} minutes")
                        return False
                    
                    retries += 1
                    if retries < self.max_retries:
                        logger.info(f"Retrying report generation (attempt {retries + 1} of {self.max_retries})")
                        time.sleep(60)  # Ждем минуту перед повторной попыткой
                    
                except Exception as e:
                    logger.error(f"Error in report job: {str(e)}", exc_info=True)
                    retries += 1
                    if retries < self.max_retries:
                        logger.info(f"Retrying after error (attempt {retries + 1} of {self.max_retries})")
                        time.sleep(60)
                    else:
                        logger.error("Maximum retries reached, giving up")
                        return False
            
            return False
        finally:
            ReportJob._is_running = False
            ReportJob._lock.release()
            logger.info("Report job lock released") 