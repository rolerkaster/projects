import os
import threading
from datetime import datetime
from functools import wraps
from flask import request, jsonify
import git
import logging

# Настройка логирования
logging.basicConfig(
    filename='git_hooks.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Семафор для контроля одновременного доступа
update_lock = threading.Semaphore(1)
is_updating = False

def get_client_ip():
    """Получение IP-адреса клиента"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def requires_secret_key(f):
    """Декоратор для проверки секретного ключа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        secret_key = request.args.get('secret_key')
        if not secret_key:
            return jsonify({'error': 'Secret key is required'}), 400
            
        expected_key = os.getenv('GIT_WEBHOOK_SECRET_KEY')
        if not expected_key:
            return jsonify({'error': 'Server configuration error'}), 500
            
        if secret_key != expected_key:
            return jsonify({'error': 'Invalid secret key'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

def init_git_hooks(app):
    @app.route('/hooks/git', methods=['POST'])
    @requires_secret_key
    def git_webhook():
        global is_updating
        
        # Проверяем, не выполняется ли уже обновление
        if is_updating:
            return jsonify({'message': 'Update is already in progress'}), 409
            
        # Пытаемся захватить семафор
        if not update_lock.acquire(blocking=False):
            return jsonify({'message': 'Update is already in progress'}), 409
            
        try:
            is_updating = True
            client_ip = get_client_ip()
            
            # Логируем начало обновления
            logging.info(f'Update started - Date: {datetime.now()}, IP: {client_ip}')
            
            repo = git.Repo('.')
            
            # Переключаемся на главную ветку
            current = repo.active_branch
            if current.name != 'main':
                logging.info('Switching to main branch')
                repo.git.checkout('main')
            
            # Отменяем локальные изменения
            logging.info('Resetting local changes')
            repo.git.reset('--hard')
            
            # Получаем обновления
            logging.info('Pulling updates from remote')
            repo.remotes.origin.pull()
            
            logging.info('Update completed successfully')
            return jsonify({'message': 'Repository updated successfully'})
            
        except Exception as e:
            logging.error(f'Update failed: {str(e)}')
            return jsonify({'error': f'Update failed: {str(e)}'}), 500
            
        finally:
            is_updating = False
            update_lock.release() 