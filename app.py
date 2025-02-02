from flask import Flask, request, jsonify
import sqlite3
import platform

# Создание экземпляра Flask-приложения
app = Flask(__name__)

# Конфигурация приложения
app.config['LOCALE'] = 'ru_RU'
app.config['TIMEZONE'] = 'Europe/Moscow'

# Функция для подключения к базе данных SQLite
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Роут для получения информации о сервере
@app.route('/info/server', methods=['GET'])
def server_info():
    python_version = platform.python_version()
    return jsonify({'python_version': python_version})

# Роут для получения информации о клиенте
@app.route('/info/client', methods=['GET'])
def client_info():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    return jsonify({'ip': client_ip, 'user_agent': user_agent})

# Роут для получения информации о базе данных
@app.route('/info/database', methods=['GET'])
def database_info():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sqlite_version() AS version")
    db_info = cursor.fetchone()
    conn.close()
    return jsonify({'database_version': db_info['version']})

# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)