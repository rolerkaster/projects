from flask import send_file, request, jsonify, make_response
from app.utils.excel_utils import ExcelExporter, ExcelImporter, ImportMode, ErrorHandlingMode
import tempfile
import os
from functools import wraps
from app.models import Permission
import logging
from datetime import datetime
import mimetypes

def require_permission(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            logging.info(f"Checking permission in decorator: {permission_name}")
            has_permission = Permission.check_permission(permission_name)
            logging.info(f"Permission check result: {has_permission}")
            if not has_permission:
                return jsonify({"error": "Недостаточно прав"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class ExportImportController:
    ENTITY_TYPES = ['users', 'roles']
    
    EXCLUDED_COLUMNS = {
        'users': ['password_hash', 'created_at', 'updated_at', 'deleted_at', 'deleted_by'],
        'roles': ['created_at', 'updated_at', 'deleted_at', 'deleted_by', 'created_by']
    }

    ALLOWED_MIME_TYPES = [
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-excel'
    ]

    @staticmethod
    @require_permission("export_data")
    def export_entity(entity_type: str):
        logging.info(f"Starting export for entity type: {entity_type}")
        if entity_type not in ExportImportController.ENTITY_TYPES:
            return jsonify({"error": "Неизвестный тип сущности"}), 400
            
        try:
            wb = ExcelExporter.export_entities(
                entity_type,
                exclude_columns=ExportImportController.EXCLUDED_COLUMNS.get(entity_type, [])
            )
            
            # Создаем временный файл
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{entity_type}_export_{timestamp}.xlsx"
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
                wb.save(tmp.name)
                tmp_path = tmp.name

            # Отправляем файл
            response = make_response(send_file(
                tmp_path,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            ))
            
            # Добавляем заголовки для правильной обработки файла
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
            
            # Удаляем временный файл после отправки
            @response.call_on_close
            def cleanup():
                try:
                    os.unlink(tmp_path)
                except:
                    pass
                    
            return response
            
        except Exception as e:
            logging.error(f"Error during export: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @staticmethod
    @require_permission("import_data")
    def import_entity(entity_type: str):
        if entity_type not in ExportImportController.ENTITY_TYPES:
            return jsonify({"error": "Неизвестный тип сущности"}), 400
            
        if "file" not in request.files:
            return jsonify({"error": "Файл не найден"}), 400
            
        file = request.files["file"]
        logging.info(f"Received file: {file.filename}")
        
        if not file.filename:
            return jsonify({"error": "Пустое имя файла"}), 400
            
        if not file.filename.endswith(".xlsx"):
            return jsonify({"error": "Неверный формат файла. Ожидается .xlsx"}), 400
            
        # Проверяем MIME тип
        mime_type = file.content_type
        logging.info(f"File MIME type: {mime_type}")
        
        if mime_type not in ExportImportController.ALLOWED_MIME_TYPES:
            return jsonify({"error": f"Неверный тип файла. Получен: {mime_type}"}), 400
            
        # Получаем параметры импорта
        import_mode = request.form.get("import_mode", ImportMode.ADD_ONLY)
        error_handling = request.form.get("error_handling", ErrorHandlingMode.CONTINUE_ON_ERROR)
        
        logging.info(f"Import mode: {import_mode}, Error handling: {error_handling}")
        
        # Сохраняем файл временно
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name
                logging.info(f"Saved temporary file: {tmp_path}")
                
                # Проверяем размер файла
                file_size = os.path.getsize(tmp_path)
                logging.info(f"File size: {file_size} bytes")
                
                if file_size == 0:
                    return jsonify({"error": "Файл пуст"}), 400
                
                try:
                    # Импортируем данные
                    result = ExcelImporter.import_entities(
                        tmp_path,
                        entity_type,
                        import_mode=import_mode,
                        error_handling=error_handling,
                        exclude_columns=ExportImportController.EXCLUDED_COLUMNS.get(entity_type, [])
                    )
                    
                    # Формируем ответ
                    response = {
                        "success": {
                            "added": [
                                {
                                    "message": f"Запись №{item['row']} успешно добавлена с идентификатором №{item['db_id']}",
                                    "temp_password": item.get('temp_password', None)
                                } if entity_type == 'users' else
                                f"Запись №{item['row']} успешно добавлена с идентификатором №{item['db_id']}"
                                for item in result.success_added
                            ],
                            "updated": [
                                f"Запись №{item['row']} успешно обновила запись с идентификатором №{item['db_id']}"
                                for item in result.success_updated
                            ]
                        },
                        "errors": [
                            f"Запись №{item['row']} не удалось добавить/обновить. {item['error']}"
                            for item in result.errors
                        ],
                        "duplicates": [
                            f"Запись №{item['row']} содержит дубликат записи №{item['db_id']} по свойству {item['property']}"
                            for item in result.duplicates
                        ]
                    }
                    
                    return jsonify(response)
                    
                except Exception as e:
                    logging.error(f"Error during import: {str(e)}")
                    return jsonify({"error": str(e)}), 500
                    
        except Exception as e:
            logging.error(f"Error saving temporary file: {str(e)}")
            return jsonify({"error": "Ошибка при сохранении файла"}), 500
            
        finally:
            # Удаляем временный файл
            try:
                if 'tmp_path' in locals():
                    os.unlink(tmp_path)
                    logging.info("Temporary file deleted")
            except Exception as e:
                logging.error(f"Error deleting temporary file: {str(e)}")
                pass 