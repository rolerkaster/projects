from flask import jsonify, request
from app.models.log_request import LogRequest
from app.dtos.log_request_dto import LogRequestDTO, LogRequestShortDTO, LogRequestCollectionDTO


class LogRequestController:
    @staticmethod
    def get_logs():
        # Получаем параметры запроса
        page = request.args.get('page', 1, type=int)
        count = request.args.get('count', 10, type=int)
        sort_by = request.json.get('sortBy', []) if request.json else []
        filters = request.json.get('filter', []) if request.json else []

        # Получаем логи
        result = LogRequest.get_all(
            page=page,
            per_page=count,
            sort_by=sort_by,
            filters=filters
        )

        # Преобразуем в DTO
        collection = LogRequestCollectionDTO.from_dict(result)
        return jsonify(collection), 200

    @staticmethod
    def get_log(log_id):
        log = LogRequest.get_by_id(log_id)
        if log is None:
            return jsonify({'error': 'Log not found'}), 404
        
        # Преобразуем в DTO
        log_dto = LogRequestDTO.from_dict(log)
        return jsonify(log_dto), 200

    @staticmethod
    def delete_log(log_id):
        if LogRequest.delete(log_id):
            return jsonify({'message': f'Log with ID {log_id} has been successfully deleted'}), 200
        return jsonify({'error': 'Log not found'}), 404 