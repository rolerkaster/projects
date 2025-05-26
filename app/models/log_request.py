import sqlite3
import json
from datetime import datetime, timedelta
from migrations.migrations import get_db_connection


class LogRequest:
    @staticmethod
    def create(api_path, http_method, controller_path, controller_method, 
               request_body, request_headers, user_id, ip_address, user_agent,
               response_status, response_body, response_headers):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO LogsRequests (
                api_path, http_method, controller_path, controller_method,
                request_body, request_headers, user_id, ip_address,
                user_agent, response_status, response_body, response_headers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            api_path, http_method, controller_path, controller_method,
            request_body, json.dumps(request_headers), user_id, ip_address,
            user_agent, response_status, response_body, json.dumps(response_headers)
        ))
        
        conn.commit()
        conn.close()

    @staticmethod
    def get_all(page=1, per_page=10, sort_by=None, filters=None):
        conn = get_db_connection()
        cursor = conn.cursor()

        # Базовый запрос
        query = '''
            SELECT id, api_path, controller_path, controller_method,
                   response_status, created_at
            FROM LogsRequests
            WHERE 1=1
        '''
        params = []

        # Применяем фильтры
        if filters:
            for f in filters:
                if f['key'] == 'user_id':
                    query += ' AND user_id = ?'
                    params.append(f['value'])
                elif f['key'] == 'status':
                    query += ' AND response_status = ?'
                    params.append(int(f['value']))
                elif f['key'] == 'ip_address':
                    query += ' AND ip_address = ?'
                    params.append(f['value'])
                elif f['key'] == 'user_agent':
                    query += ' AND user_agent LIKE ?'
                    params.append(f'%{f["value"]}%')
                elif f['key'] == 'controller':
                    query += ' AND controller_path LIKE ?'
                    params.append(f'%{f["value"]}%')

        # Применяем сортировку
        if sort_by:
            order_clauses = []
            for sort in sort_by:
                direction = 'DESC' if sort['order'].lower() == 'desc' else 'ASC'
                order_clauses.append(f'{sort["key"]} {direction}')
            if order_clauses:
                query += ' ORDER BY ' + ', '.join(order_clauses)
        else:
            query += ' ORDER BY created_at DESC'

        # Получаем общее количество записей
        count_query = f'''
            SELECT COUNT(*) as total
            FROM ({query})
        '''
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Применяем пагинацию
        query += ' LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])

        cursor.execute(query, params)
        logs = cursor.fetchall()

        result = {
            'items': [{
                'api_path': log['api_path'],
                'controller_path': log['controller_path'],
                'controller_method': log['controller_method'],
                'response_status': log['response_status'],
                'created_at': log['created_at']
            } for log in logs],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }

        conn.close()
        return result

    @staticmethod
    def get_by_id(log_id):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM LogsRequests WHERE id = ?', (log_id,))
        log = cursor.fetchone()
        
        if log:
            result = dict(log)
            result['request_headers'] = json.loads(result['request_headers'])
            result['response_headers'] = json.loads(result['response_headers'])
        else:
            result = None

        conn.close()
        return result

    @staticmethod
    def delete(log_id):
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM LogsRequests WHERE id = ?', (log_id,))
        deleted = cursor.rowcount > 0

        conn.commit()
        conn.close()
        return deleted

    @staticmethod
    def cleanup_old_logs():
        conn = get_db_connection()
        cursor = conn.cursor()

        # Удаляем логи старше 73 часов
        cutoff_time = (datetime.utcnow() - timedelta(hours=73)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('DELETE FROM LogsRequests WHERE created_at < ?', (cutoff_time,))

        conn.commit()
        conn.close() 