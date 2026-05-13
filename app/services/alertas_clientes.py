from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

TZ_EC = ZoneInfo("America/Guayaquil")


def _to_ec_date(value):
    if not value:
        return None

    if isinstance(value, datetime):
        return value.date()
    elif isinstance(value, date):
        return value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            try:
                return date.fromisoformat(value[:10])
            except Exception:
                return None
    else:
        return None

    return dt.date()


def _ultima_fecha_hasta(db, cliente_id):
    venta = db["ventas"].find_one(
        {"cliente_id": cliente_id},
        sort=[("fecha", -1)],
        projection={"membresia.fecha_hasta": 1},
    )
    return _to_ec_date(((venta or {}).get("membresia") or {}).get("fecha_hasta"))


def cerrar_alertas_vencimiento_cliente(db, cliente_id, *, motivo="renovacion"):
    """Cierra solo alertas de vencimiento del cliente.

    Las notificaciones de tipo "renovacion" son usadas por administrador y
    cajero, asi que no deben marcarse como vistas desde el flujo del cliente.
    """
    ahora = datetime.now(timezone.utc)
    noti_col = db["notificaciones"]

    noti_col.update_many(
        {
            "cliente_id": cliente_id,
            "tipo": {
                "$in": [
                    "membresia_5_dias",
                    "membresia_3_dias",
                    "membresia_2_dias",
                    "membresia_1_dia",
                ]
            },
            "$or": [
                {"estado": "activa"},
                {"leido": False},
                {"visto": False},
            ],
        },
        {
            "$set": {
                "estado": "cerrada",
                "leido": True,
                "visto": True,
                "cerrada": ahora,
                "cerrada_por_sistema": True,
                "motivo_cierre": motivo,
            }
        },
    )


def limpiar_alertas_renovacion_obsoletas(db, filtro_extra=None):
    """Oculta notificaciones de renovacion cuya fecha ya no es la ultima del cliente."""
    noti_col = db["notificaciones"]
    filtro = {"tipo": "renovacion", "cliente_id": {"$exists": True}, "visto": False}
    if filtro_extra:
        filtro.update(filtro_extra)

    docs = list(noti_col.find(filtro, {"cliente_id": 1, "fecha_hasta": 1}).limit(500))
    if not docs:
        return 0

    ahora = datetime.now(timezone.utc)
    cerradas = 0

    for doc in docs:
        cliente_id = doc.get("cliente_id")
        fecha_alerta = _to_ec_date(doc.get("fecha_hasta"))
        fecha_actual = _ultima_fecha_hasta(db, cliente_id)

        if not fecha_actual or fecha_actual != fecha_alerta:
            res = noti_col.update_one(
                {"_id": doc["_id"], "visto": False},
                {
                    "$set": {
                        "visto": True,
                        "visto_at": ahora,
                        "cerrada_por_sistema": True,
                        "motivo_cierre": "membresia_renovada",
                    }
                },
            )
            cerradas += res.modified_count

    return cerradas


def obtener_clientes_por_vencer(db, dias_objetivo=(2, 1, 0), limitar=50):

    ventas_col = db["ventas"]
    clientes_col = db["clientes"]

    hoy_ec = datetime.now(timezone.utc).astimezone(TZ_EC).date()

    pipeline = [
        {"$sort": {"fecha": -1}},  
        {"$group": {
            "_id": "$cliente_id",
            "venta": {"$first": "$$ROOT"}
        }},
        {"$limit": int(limitar)},
    ]

    ultimas = list(ventas_col.aggregate(pipeline))

    ids = []
    tmp = {}  

    for row in ultimas:
        cliente_id = row["_id"]
        venta = row.get("venta") or {}
        membresia = (venta.get("membresia") or {})
        fh = membresia.get("fecha_hasta")

        if not fh:
            continue

        fh_ec = _to_ec_date(fh)
        if not fh_ec:
            continue

        dias_restantes = (fh_ec - hoy_ec).days  

        no_renovo = (dias_restantes < 0)

        if (dias_restantes in dias_objetivo) or no_renovo:
            ids.append(cliente_id)
            tmp[cliente_id] = {
                "dias_restantes": int(dias_restantes),
                "fecha_hasta": fh_ec.isoformat(),
                "no_renovo": bool(no_renovo),
            }

    if not ids:
        return []

    clientes = list(clientes_col.find(
        {"_id": {"$in": ids}},
        {"nombre": 1, "apellido": 1, "telefono": 1, "email": 1, "identificacion": 1, "activo": 1}
    ))

    out = []
    for c in clientes:
        cid = c["_id"]
        calc = tmp.get(cid, {})
        nombre = f"{c.get('nombre','')} {c.get('apellido','')}".strip() or "-"
        out.append({
            "_id": str(cid),
            "nombre": nombre,
            "identificacion": c.get("identificacion",""),
            "telefono": c.get("telefono",""),
            "email": c.get("email",""),
            "activo": bool(c.get("activo", True)),
            "dias_restantes": calc.get("dias_restantes"),
            "fecha_hasta": calc.get("fecha_hasta"),
            "no_renovo": calc.get("no_renovo"),
        })

    out.sort(key=lambda x: (x["dias_restantes"], x["nombre"]))
    return out
