from datetime import datetime, timezone, timedelta
import app.extensions as extensions


def get_horarios_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios"]


def get_config_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios_config"]


def get_overrides_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios_overrides"]


def get_default_config():
    cfg = get_config_collection()
    doc = cfg.find_one({"_id": "default"})
    if doc:
        return doc

    # crear default si no existe
    doc = {
        "_id": "default",
        "bloques": [{"ini": "05:00", "fin": "12:00"}, {"ini": "15:00", "fin": "22:00"}],
        "slot_minutes": 60,
        "cupo_maximo": 10,
        "updated_at": datetime.now(timezone.utc),
    }
    cfg.insert_one(doc)
    return doc


def get_override_for_day(fecha_day_utc: datetime):
    ov = get_overrides_collection()
    return ov.find_one({"fecha": fecha_day_utc})


def _generate_slots_docs(fecha_day_utc: datetime, bloques, slot_minutes: int, cupo_maximo: int, is_override: bool):
    docs = []
    for b in bloques:
        sh, sm = [int(x) for x in b["ini"].split(":")]
        eh, em = [int(x) for x in b["fin"].split(":")]

        start_dt = fecha_day_utc.replace(hour=sh, minute=sm, second=0, microsecond=0)
        end_dt = fecha_day_utc.replace(hour=eh, minute=em, second=0, microsecond=0)

        cur = start_dt
        while cur < end_dt:
            fin = cur + timedelta(minutes=slot_minutes)
            if fin > end_dt:
                break

            docs.append({
                "fecha": fecha_day_utc,
                "inicio": cur,
                "fin": fin,
                "cupo_maximo": int(cupo_maximo),
                "cupo_usado": 0,
                "estado": "activo",
                "is_override": bool(is_override),
                "created_at": datetime.now(timezone.utc),
            })
            cur = fin
    return docs


def ensure_slots_for_day(fecha_day_utc: datetime):
    """
    Si no existen slots para ese día, los genera con override o default config.
    """
    horarios = get_horarios_collection()

    exists = horarios.count_documents({"fecha": fecha_day_utc, "estado": "activo"}) > 0
    if exists:
        return

    override = get_override_for_day(fecha_day_utc)
    if override:
        bloques = override["bloques"]
        slot_minutes = int(override["slot_minutes"])
        cupo_maximo = int(override["cupo_maximo"])
        is_override = True
    else:
        cfg = get_default_config()
        bloques = cfg["bloques"]
        slot_minutes = int(cfg["slot_minutes"])
        cupo_maximo = int(cfg["cupo_maximo"])
        is_override = False

    docs = _generate_slots_docs(fecha_day_utc, bloques, slot_minutes, cupo_maximo, is_override)

    if docs:
        horarios.insert_many(docs)


def listar_slots_por_fecha(fecha_day_utc: datetime):
    horarios = get_horarios_collection()
    return list(horarios.find({"fecha": fecha_day_utc, "estado": "activo"}).sort("inicio", 1))
