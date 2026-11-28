"""Flask application factory for UniSecure (Phase 1 Skeleton)."""

from pathlib import Path

from flask import Flask, request

from app.models.db import close_db
from config.settings import Config
from database.init_db import init_db


def create_app(config_override: dict | None = None) -> Flask:
    """Create and configure the UniSecure Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(Config)
    if config_override:
        app.config.update(config_override)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    init_db(app.config["DATABASE_PATH"], app.config["UPLOAD_FOLDER"])

    app.teardown_appcontext(close_db)

    @app.after_request
    def apply_cors(response):
        # Phase 1 skeleton uses configurable CORS origin (defaults to '*' in dev).
        origin = request.headers.get("Origin")
        configured = app.config.get("CORS_ALLOW_ORIGIN", "*")
        if configured == "*" and origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        else:
            response.headers["Access-Control-Allow-Origin"] = configured
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        return response

    from app.routes.api import api_bp
    from app.routes.web import web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    return app
