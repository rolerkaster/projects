import logging
from app import create_app, shutdown_scheduler
from migrations.migrations import run_migrations
from migrations.seeds import seed_data
import atexit

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    try:
        logger.info("Starting application...")
        run_migrations()
        seed_data()
        
        app = create_app()
        
        # Регистрируем функцию завершения работы планировщика
        atexit.register(shutdown_scheduler)
        
        logger.info("Application started successfully")
        app.run(debug=True, use_reloader=False)  # Отключаем reloader, чтобы избежать двойного запуска планировщика
    except Exception as e:
        logger.error(f"Error starting application: {str(e)}")
        raise