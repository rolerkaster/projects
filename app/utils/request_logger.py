from flask import request, g
from app.models.log_request import LogRequest


class RequestLogger:
    @staticmethod
    def before_request():
        # Сохраняем время начала запроса
        g.request_start_time = request.environ.get('REQUEST_TIME')

    @staticmethod
    def after_request(response):
        # Пропускаем логирование для запросов к статическим файлам
        if request.path.startswith('/static/'):
            return response

        try:
            # Получаем тело запроса
            request_body = request.get_data(as_text=True)
            if not request_body and request.form:
                request_body = dict(request.form)
            elif not request_body and request.json:
                request_body = request.json

            # Создаем запись лога
            LogRequest.create(
                api_path=request.path,
                http_method=request.method,
                controller_path=request.endpoint if request.endpoint else '',
                controller_method=request.endpoint.split('.')[-1] if request.endpoint else '',
                request_body=str(request_body) if request_body else None,
                request_headers=dict(request.headers),
                user_id=g.user.username if hasattr(g, 'user') and g.user else None,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                response_status=response.status_code,
                response_body=response.get_data(as_text=True),
                response_headers=dict(response.headers)
            )

            # Очищаем старые логи
            LogRequest.cleanup_old_logs()

        except Exception as e:
            # В случае ошибки логирования не прерываем выполнение запроса
            print(f"Error logging request: {str(e)}")

        return response 