import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logger(name, log_file, level=logging.INFO):
    """Настройка логгера с ротацией файлов"""
    
    # Создаем директорию для логов если её нет
    os.makedirs('logs', exist_ok=True)
    
    # Создаем форматтер
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Создаем хендлер для файла с ротацией
    file_handler = RotatingFileHandler(
        f'logs/{log_file}',
        maxBytes=1024 * 1024,  # 1MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    
    # Создаем хендлер для консоли
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Получаем логгер
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Очищаем существующие хендлеры
    logger.handlers = []
    
    # Добавляем хендлеры
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger 