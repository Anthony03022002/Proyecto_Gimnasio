from flask import jsonify
from . import api_bp
from app.extensions import mongo_db
from app.services.user_service import get_users_collection, create_cajero, list_cajeros



@api_bp.get("/health")
def health_check():
    try:
        mongo_db.command("ping")
        mongo_status = "ok"
    except Exception as e:
        mongo_status = f"error: {e}"

    return jsonify({
        "status": "ok",
        "mongo": mongo_status
    }), 200
