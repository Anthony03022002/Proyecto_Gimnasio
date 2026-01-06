from bson import ObjectId
from datetime import datetime, timezone, timedelta
import app.extensions as extensions

TZ_GYE = timezone(timedelta(hours=-5))


def get_reservas_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["reservas"]

def obtener_clases_hoy_entrenador(entrenador_id: str):
    col = get_reservas_collection()  # db["reservas"]

    ahora_local = datetime.now(TZ_GYE)
    hoy_str = ahora_local.strftime("%Y-%m-%d")  # "2026-01-05"

    try:
        entrenador_oid = ObjectId(str(entrenador_id))
    except Exception:
        raise ValueError("ID de entrenador inválido")

    pipeline = [
        {
            "$match": {
                "entrenador_id": entrenador_oid,
                "estado": {"$ne": "cancelada"},
                "fecha": hoy_str,
            }
        },
        {
            "$lookup": {
                "from": "clientes",          # ✅ cambia si tu colección tiene otro nombre
                "localField": "cliente_id",
                "foreignField": "_id",
                "as": "cliente",
            }
        },
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {
            "$addFields": {
                # ✅ nombre completo para el template
                "cliente_nombre": {
                    "$trim": {
                        "input": {
                            "$concat": [
                                {"$ifNull": ["$cliente.nombre", ""]},
                                " ",
                                {"$ifNull": ["$cliente.apellido", ""]},
                            ]
                        }
                    }
                }
            }
        },
        {
            "$project": {
                "_id": 1,
                "cliente_id": 1,
                "slot_id": 1,
                "fecha": 1,
                "entrenador_id": 1,
                "estado": 1,
                "creado": 1,
                "cliente_nombre": 1,
            }
        },
        {"$sort": {"slot_id": -1}},  # ✅ más recientes primero (por hora del día)
    ]

    reservas_hoy = list(col.aggregate(pipeline))
    return ahora_local, reservas_hoy, TZ_GYE