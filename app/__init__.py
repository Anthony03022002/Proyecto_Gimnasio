from flask import Flask
from .config import Config
from .extensions import init_extensions
from .api import api_bp
from .web import web_bp


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB


    app.config.from_object(Config)

    # 1) Inicializamos extensiones (Mongo, bcrypt, jwt)
    init_extensions(app)

    # 2) Dentro del app_context creamos el admin por defecto
    from .services.user_service import create_default_admin
    with app.app_context():
        create_default_admin()

    # 3) Registramos blueprints
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(web_bp)

    return app

