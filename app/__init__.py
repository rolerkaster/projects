from flask import Flask
import logging
import sys


# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)


from app.routes.auth import auth_bp
from app.routes.role import role_bp
from app.routes.permission import permission_bp
from app.routes.user import user_bp
from app.routes.user_role import user_role_bp
from app.routes.role_permission import role_perm_bp
from app.routes.changelog import changelog_bp
from app.routes.log_request_routes import log_request_routes
from app.routes.report import report_bp
from app.utils.request_logger import RequestLogger
from app.git_hooks import init_git_hooks
from app.services.scheduler_service import SchedulerService
from dotenv import load_dotenv

scheduler = None

def create_app():
    global scheduler
    
    # Загружаем переменные окружения
    load_dotenv()
    
    app = Flask(__name__)
    

    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(role_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(permission_bp, url_prefix='/api/ref/policy/permission')
    app.register_blueprint(user_bp, url_prefix='/api/ref/user')
    app.register_blueprint(user_role_bp, url_prefix='/api/ref/user')
    app.register_blueprint(role_perm_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(changelog_bp, url_prefix='/api/ref/changelog')
    app.register_blueprint(log_request_routes)
    app.register_blueprint(report_bp, url_prefix='/api/report')
    
    # Регистрируем middleware для логирования
    app.before_request(RequestLogger.before_request)
    app.after_request(RequestLogger.after_request)
    
    # Инициализируем обработчик git-хуков
    init_git_hooks(app)
    
    # Инициализируем и запускаем планировщик
    scheduler = SchedulerService()
    scheduler.start()
    
    return app

def shutdown_scheduler():
    global scheduler
    if scheduler:
        scheduler.stop()