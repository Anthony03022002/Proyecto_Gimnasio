from datetime import datetime, timezone
import app.extensions as extensions

DAYS = ["mon","tue","wed","thu","fri","sat","sun"]

def get_weekly_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios_semana"]

def get_weekly_config():
    col = get_weekly_collection()
    doc = col.find_one({"_id": "weekly"})
    if doc:
        return doc

    # default inicial
    doc = {
        "_id": "weekly",
        "timezone": "America/Guayaquil",
        "slot_minutes": 60,
        "cupo_maximo": 10,
        "days": {k: {"enabled": False, "bloques": []} for k in DAYS},
        "updated_at": datetime.now(timezone.utc),
    }
    col.insert_one(doc)
    return doc

def save_weekly_config(slot_minutes: int, cupo_maximo: int, days_dict: dict):
    col = get_weekly_collection()
    col.update_one(
        {"_id": "weekly"},
        {"$set": {
            "slot_minutes": int(slot_minutes),
            "cupo_maximo": int(cupo_maximo),
            "days": days_dict,
            "updated_at": datetime.now(timezone.utc),
        }},
        upsert=True
    )
