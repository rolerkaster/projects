import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')
MAX_TOKENS = int(os.environ.get('MAX_TOKENS', 5))
TOKEN_LIFETIME = int(os.environ.get('TOKEN_LIFETIME', 3600))
TWO_FACTOR_CODE_TTL = int(os.getenv("TWO_FACTOR_CODE_TTL", 300))