from flask import Flask
from app.routes.auth import auth_bp
from app.routes.role import role_bp
from app.routes.permission import permission_bp
from app.routes.user import user_bp
from app.routes.user_role import user_role_bp
from app.routes.role_permission import role_perm_bp
from app.routes.changelog import changelog_bp

def create_app():
    app = Flask(__name__)
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(role_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(permission_bp, url_prefix='/api/ref/policy/permission')
    app.register_blueprint(user_bp, url_prefix='/api/ref/user')
    app.register_blueprint(user_role_bp, url_prefix='/api/ref/user')
    app.register_blueprint(role_perm_bp, url_prefix='/api/ref/policy/role')
    app.register_blueprint(changelog_bp, url_prefix='/api/ref/changelog')
    return app