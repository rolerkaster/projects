import re
from datetime import datetime
import logging

def validate_username(username):
    return re.match(r'^[A-Z][a-zA-Z]{6,}$', username) is not None

def validate_password(password):
    return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]', password) and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password)

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) is not None

def parse_date(date_str):
    """Пытается распарсить дату из разных форматов."""
    formats = [
        '%Y-%m-%d',  # 2005-12-12
        '%d.%m.%Y',  # 12.12.2005
        '%Y.%m.%d',  # 2005.12.12
        '%m/%d/%Y',  # 12/12/2005
        '%Y/%m/%d',  # 2005/12/12
    ]
    
    # Если date_str уже является объектом datetime, возвращаем его
    if isinstance(date_str, datetime):
        return date_str
        
    logging.info(f"Parsing date: {date_str}, type: {type(date_str)}")
    
    for fmt in formats:
        try:
            return datetime.strptime(str(date_str), fmt)
        except (ValueError, TypeError):
            continue
    return None

def validate_birthday(birthday_str):
    try:
        logging.info(f"Validating birthday: {birthday_str}, type: {type(birthday_str)}")
        birth_date = parse_date(birthday_str)
        if not birth_date:
            logging.info("Birthday parsing failed")
            return False
            
        today = datetime.now()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        logging.info(f"Calculated age: {age}")
        return age >= 14
    except Exception as e:
        logging.error(f"Error validating birthday: {str(e)}")
        return False