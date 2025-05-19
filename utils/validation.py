import re
from datetime import datetime

def validate_username(username):
    return re.match(r'^[A-Z][a-zA-Z]{6,}$', username) is not None

def validate_password(password):
    return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[!@#$%^&*(),.?":{}|<>]', password) and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password)

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) is not None

def validate_birthday(birthday_str):
    try:
        birth_date = datetime.strptime(birthday_str, '%Y-%m-%d')
        today = datetime.now()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age >= 14
    except ValueError:
        return False