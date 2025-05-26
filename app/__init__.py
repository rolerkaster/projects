from flask import Flask
from flask.helpers import url_for
from werkzeug.utils import redirect
from app.routes.auth import auth_bp
from app.routes.role import role_bp
from app.routes.permission import permission_bp
from app.routes.user import user_bp
from app.routes.user_role import user_role_bp
from app.routes.role_permission import role_perm_bp
from app.routes.changelog import changelog_bp
from app.routes.log import log_bp
from app.utils.request_logger import RequestLogger
from app.git_hooks import init_git_hooks
from dotenv import load_dotenv
from app.scheduler import init_scheduler, shutdown_scheduler
from app.utils.logger import setup_logger
import atexit
import os

# Создаем директории
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# Настраиваем логгер
logger = setup_logger('FlaskApp', 'app.log')

def create_app():
    # Загружаем переменные окружения
    load_dotenv()
    
    app = Flask(__name__)
    
    # Отключаем автоматическое добавление слеша
    app.url_map.strict_slashes = False
    
    # Регистрируем блюпринты
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(role_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(permission_bp, url_prefix='/api/ref/policy/permission')
    app.register_blueprint(user_bp, url_prefix='/api/ref/user')
    app.register_blueprint(user_role_bp, url_prefix='/api/ref/user')
    app.register_blueprint(role_perm_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(changelog_bp, url_prefix='/api/ref/changelog')
    app.register_blueprint(log_bp, url_prefix='/api/ref/log')
    
    # Регистрируем middleware для логирования
    app.before_request(RequestLogger.before_request)
    app.after_request(RequestLogger.after_request)
    
    # Инициализируем обработчик git-хуков
    init_git_hooks(app)
    
    # Инициализируем планировщик при запуске приложения
    @app.before_first_request
    def init_app():
        init_scheduler()
    
    # Останавливаем планировщик при выключении
    @app.teardown_appcontext
    def shutdown(exception=None):
        shutdown_scheduler()
    
    @app.route('/')
    def index():
        return 'API Server is running'
    
    return app

app = create_app()