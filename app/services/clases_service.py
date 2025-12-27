from bson import ObjectId
from datetime import datetime, timezone, timedelta
import app.extensions as extensions

TZ_GYE = timezone(timedelta(hours=-5))


def get_clases_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["clases"]


def obtener_clases_hoy_entrenador(entrenador_id: str):

    col = get_clases_collection()

    ahora_local = datetime.now(TZ_GYE)
    inicio_dia_local = ahora_local.replace(hour=0, minute=0, second=0, microsecond=0)
    fin_dia_local = ahora_local.replace(hour=23, minute=59, second=59, microsecond=999000)

    inicio_dia_utc = inicio_dia_local.astimezone(timezone.utc)
    fin_dia_utc = fin_dia_local.astimezone(timezone.utc)
    ahora_utc = ahora_local.astimezone(timezone.utc)

    try:
        entrenador_oid = ObjectId(str(entrenador_id))
    except Exception:
        raise ValueError("ID de entrenador inválido")

    q = {
        "entrenador_id": entrenador_oid,
        "estado": {"$ne": "cancelada"},
        "inicio": {"$gte": inicio_dia_utc, "$lte": fin_dia_utc},
    }

    clases_hoy = list(col.find(q).sort("inicio", 1))

    clase_actual = None
    proximas = []

    for c in clases_hoy:
        ini = c.get("inicio")
        fin = c.get("fin")
        if ini and fin and ini <= ahora_utc < fin:
            clase_actual = c
        elif ini and ini > ahora_utc:
            proximas.append(c)

    return ahora_local, clase_actual, proximas, clases_hoy, TZ_GYE
