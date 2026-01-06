from datetime import datetime, timezone
from bson import ObjectId
from flask import request, redirect, url_for, flash, session

from app import extensions

def get_reservas_collection():
    db = extensions.mongo_db
    return db["reservas"]

def get_horarios_collection():
    db = extensions.mongo_db
    return db["horarios"]  # ajusta si tu colección se llama distinto

def membresia_activa(cliente_id):
    # ✅ si quieres bloquear reservas a clientes sin membresía activa
    db = extensions.mongo_db
    ventas = db["ventas"]
    ahora = datetime.now(timezone.utc)

    last = ventas.find_one(
        {"cliente_id": cliente_id},
        sort=[("fecha", -1)],
        projection={"membresia.fecha_hasta": 1}
    )
    if not last:
        return False

    fh = (last.get("membresia") or {}).get("fecha_hasta")
    return bool(fh and fh >= ahora)
