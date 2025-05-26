from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from pytz import utc
import os
from app.jobs.report_job import ReportJob
from app.utils.logger import setup_logger

# Создаем директории
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# Настраиваем логгер
logger = setup_logger('Scheduler', 'scheduler.log')

# Глобальная переменная для хранения экземпляра планировщика
_scheduler_instance = None

def init_scheduler():
    """Инициализация и запуск планировщика задач"""
    global _scheduler_instance
    
    try:
        # Проверяем, не запущен ли уже планировщик
        if _scheduler_instance is not None:
            if _scheduler_instance.running:
                logger.warning("Scheduler is already running!")
                return _scheduler_instance
            else:
                logger.info("Found stopped scheduler instance, creating new one")
                _scheduler_instance.shutdown()
        
        # Создаем новый планировщик
        _scheduler_instance = BackgroundScheduler(timezone=utc)
        report_job = ReportJob()
        
        # Получаем интервал из переменных окружения (в минутах)
        interval_minutes = int(os.getenv('REPORT_TIMEOUT', 60))
        
        # Проверяем, нет ли уже задачи с таким ID
        if _scheduler_instance.get_job('report_job'):
            logger.warning("Report job already exists, skipping addition")
        else:
            # Добавляем задачу в планировщик
            _scheduler_instance.add_job(
                report_job.run,
                trigger=IntervalTrigger(minutes=interval_minutes, timezone=utc),
                id='report_job',
                name='Generate system usage report',
                replace_existing=True,
                coalesce=True,  # Предотвращает накопление пропущенных запусков
                max_instances=1  # Гарантирует, что одновременно выполняется только один экземпляр задачи
            )
            logger.info(f"Added report job with interval: {interval_minutes} minutes")
        
        # Запускаем планировщик
        if not _scheduler_instance.running:
            _scheduler_instance.start()
            logger.info("Scheduler started successfully")
        
        return _scheduler_instance
    except Exception as e:
        logger.error(f"Error initializing scheduler: {str(e)}", exc_info=True)
        raise

def shutdown_scheduler():
    """Безопасное выключение планировщика"""
    global _scheduler_instance
    
    if _scheduler_instance is not None and _scheduler_instance.running:
        logger.info("Shutting down scheduler...")
        _scheduler_instance.shutdown()
        _scheduler_instance = None
        logger.info("Scheduler shut down successfully") 