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

# DTO для информации о сервере
class ServerInfoDTO:
    def __init__(self, python_version):
        self.python_version = python_version

    def to_dict(self):
        return {
            "python_version": self.python_version
        }

# DTO для информации о клиенте
class ClientInfoDTO:
    def __init__(self, ip, user_agent):
        self.ip = ip
        self.user_agent = user_agent

    def to_dict(self):
        return {
            "ip": self.ip,
            "user_agent": self.user_agent
        }

# DTO для информации о базе данных
class DatabaseInfoDTO:
    def __init__(self, database_version):
        self.database_version = database_version

    def to_dict(self):
        return {
            "database_version": self.database_version
        }

# Роут для получения информации о сервере
@app.route('/info/server', methods=['GET'])
def server_info():
    python_version = platform.python_version()
    dto = ServerInfoDTO(python_version=python_version)
    return jsonify(dto.to_dict())

# Роут для получения информации о клиенте
@app.route('/info/client', methods=['GET'])
def client_info():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    dto = ClientInfoDTO(ip=client_ip, user_agent=user_agent)
    return jsonify(dto.to_dict())

# Роут для получения информации о базе данных
@app.route('/info/database', methods=['GET'])
def database_info():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sqlite_version() AS version")
    db_info = cursor.fetchone()
    conn.close()
    dto = DatabaseInfoDTO(database_version=db_info['version'])
    return jsonify(dto.to_dict())

# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)