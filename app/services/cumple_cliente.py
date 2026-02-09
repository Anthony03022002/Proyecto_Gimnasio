from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from pymongo import ReturnDocument

TZ_EC = ZoneInfo("America/Guayaquil")

def es_cumple_hoy(fecha_nacimiento):
    if not fecha_nacimiento:
        return False

    fn = None

    if isinstance(fecha_nacimiento, datetime):
        fn = fecha_nacimiento
    elif isinstance(fecha_nacimiento, str):
        s = fecha_nacimiento.strip()
        try:
            fn = datetime.strptime(s[:10], "%Y-%m-%d")
        except Exception:
            try:
                fn = datetime.strptime(s[:10], "%d/%m/%Y")
            except Exception:
                return False
    else:
        try:
            fn = fecha_nacimiento
        except Exception:
            return False

    try:
        if isinstance(fn, datetime):
            if fn.tzinfo is None:
                fn = fn.replace(tzinfo=TZ_EC)
            else:
                fn = fn.astimezone(TZ_EC)
    except Exception:
        pass

    hoy = datetime.now(TZ_EC)
    return (fn.month == hoy.month) and (fn.day == hoy.day)


def generar_notificaciones_cumple(db, para_rol="admin", para_user_id=None, entrenador_id=None, **kwargs):
    clientes_col = db["clientes"]
    noti_col = db["notificaciones"]

    now_ec = datetime.now(TZ_EC)
    mmdd = now_ec.strftime("%m-%d")  # para comparar cumpleaños "MM-DD"

    # ✅ Ajusta este campo al real de tu documento:
    # ej: cliente["fecha_nacimiento"] puede ser datetime, string, etc.
    clientes = clientes_col.find({"fecha_nacimiento": {"$exists": True, "$ne": None}})

    for c in clientes:
        fn = c.get("fecha_nacimiento")
        if not fn:
            continue

        # --- normaliza fecha nacimiento ---
        try:
            if hasattr(fn, "strftime"):
                mmdd_cli = fn.strftime("%m-%d")
            else:
                # si viene "YYYY-MM-DD"
                mmdd_cli = str(fn)[5:10]
        except Exception:
            continue

        if mmdd_cli != mmdd:
            continue

        cid = c["_id"]

        key = {
            "tipo": "cumpleanos",
            "cliente_id": cid,
            "para_rol": para_rol,
            "fecha": now_ec.strftime("%Y-%m-%d"),
        }

        # ✅ si es noti específica del entrenador (o usuario), guárdala así
        if para_user_id is not None:
            key["para_user_id"] = para_user_id

        payload = {
            "nombre": f"{c.get('nombre','')} {c.get('apellido','')}".strip(),
            "identificacion": c.get("identificacion"),
            "telefono": c.get("telefono"),
            "email": c.get("email"),
            "fecha_nacimiento": str(fn),
        }

        noti_col.find_one_and_update(
            key,
            {
                "$setOnInsert": {
                    "tipo": "cumpleanos",
                    "cliente_id": cid,
                    "para_rol": para_rol,
                    "para_user_id": para_user_id,  # puede ser None en admin/cajero
                    "creado_at": now_ec,
                    "visto": False,
                },
                "$set": {
                    "updated_at": now_ec,
                    "payload": payload,
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )