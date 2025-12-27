from datetime import datetime, timezone, timedelta, time
from bson import ObjectId
import app.extensions as extensions
from zoneinfo import ZoneInfo

DIAS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

TZ_EC = ZoneInfo("America/Guayaquil")

def a_hora_ec(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ_EC)

def get_plantillas_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios_plantillas"]


def listar_plantillas():
    col = get_plantillas_collection()
    plantillas = list(col.find({}).sort("nombre", 1))

    for p in plantillas:
        p["creado_en_ec"] = a_hora_ec(p.get("creado_en"))
        p["actualizado_en_ec"] = a_hora_ec(p.get("actualizado_en"))

    return plantillas


def _parse_hhmm(val: str) -> time:
    h, m = [int(x) for x in val.split(":")]
    return time(hour=h, minute=m)


def crear_plantilla(nombre: str, b1_ini: str, b1_fin: str, b2_ini: str, b2_fin: str, creado_por: str):
    nombre = (nombre or "").strip()
    if not nombre:
        raise ValueError("El nombre del horario es obligatorio.")

    bloques = []

    if not (b1_ini and b1_fin):
        raise ValueError("Bloque 1 es obligatorio (inicio y fin).")
    t1_ini = _parse_hhmm(b1_ini)
    t1_fin = _parse_hhmm(b1_fin)
    if t1_ini >= t1_fin:
        raise ValueError("Bloque 1 inválido: la hora de inicio debe ser menor que la de fin.")
    bloques.append({"inicio": b1_ini, "fin": b1_fin})

    if b2_ini and b2_fin:
        t2_ini = _parse_hhmm(b2_ini)
        t2_fin = _parse_hhmm(b2_fin)
        if t2_ini >= t2_fin:
            raise ValueError("Bloque 2 inválido: la hora de inicio debe ser menor que la de fin.")
        bloques.append({"inicio": b2_ini, "fin": b2_fin})

    col = get_plantillas_collection()

    if col.find_one({"nombre": nombre}):
        raise ValueError("Ya existe un horario con ese nombre.")

    # ✅ Guardar en UTC (lo correcto)
    ahora_utc = datetime.now(timezone.utc)

    doc = {
        "nombre": nombre,
        "bloques": bloques,
        "creado_por": creado_por,
        "creado_en": ahora_utc,
        "actualizado_en": ahora_utc,
        "zona_horaria": "America/Guayaquil",
    }
    res = col.insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


def get_plantilla_por_id(plantilla_id):
    if not plantilla_id:
        return None
    if isinstance(plantilla_id, str):
        try:
            plantilla_id = ObjectId(plantilla_id)
        except Exception:
            return None
    col = get_plantillas_collection()
    return col.find_one({"_id": plantilla_id})


def get_config_semanal_collection():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    return db["horarios_semana"]


def get_config_semanal():
    col = get_config_semanal_collection()
    doc = col.find_one({"_id": "semanal"})
    if doc:
        return doc

    ahora = datetime.now(timezone.utc)

    doc = {
        "_id": "semanal",
        "zona_horaria": "America/Guayaquil",
        "intervalo_minutos": 60,
        "cupo_maximo": 10,

        "dias": {k: {"activo": False, "plantilla_id": None} for k in DIAS},
        "actualizado_en": ahora,
    }
    col.insert_one(doc)
    return doc


def guardar_config_semanal(intervalo_minutos: int, cupo_maximo: int, dias_dict: dict):
    col = get_config_semanal_collection()
    col.update_one(
        {"_id": "semanal"},
        {"$set": {
            "intervalo_minutos": int(intervalo_minutos),
            "cupo_maximo": int(cupo_maximo),
            "dias": dias_dict,
            "actualizado_en": datetime.now(timezone.utc),
        }},
        upsert=True
    )


def asignar_plantilla_a_dias(dias_a_setear, plantilla_id):
    cfg = get_config_semanal()
    dias = cfg.get("dias") or {}

    if isinstance(plantilla_id, str):
        plantilla_id = ObjectId(plantilla_id)

    for d in dias_a_setear:
        if d in DIAS:
            dias[d] = {"activo": True, "plantilla_id": plantilla_id}

    guardar_config_semanal(cfg.get("intervalo_minutos", 60), cfg.get("cupo_maximo", 10), dias)


def resolver_bloques_del_dia(dia_cfg: dict):
    if not dia_cfg or not dia_cfg.get("activo"):
        return []

    if dia_cfg.get("bloques"):
        bloques = dia_cfg.get("bloques") or []
        return [
            {"inicio": b.get("inicio") or b.get("ini"), "fin": b.get("fin")}
            for b in bloques
            if (b.get("inicio") or b.get("ini")) and b.get("fin")
        ]

    tpl = get_plantilla_por_id(dia_cfg.get("plantilla_id"))
    if not tpl:
        return []

    bloques = tpl.get("bloques") or []
    out = []
    for b in bloques:
        ini = b.get("inicio") or b.get("ini")
        fin = b.get("fin")
        if ini and fin:
            out.append({"inicio": ini, "fin": fin})
    return out


def construir_slots_para_fecha(d, bloques, intervalo_minutos: int, cupo_maximo: int):
    slots = []
    if not bloques:
        return slots

    for b in bloques:
        ini = b.get("inicio") or b.get("ini")
        fin_txt = b.get("fin")
        if not ini or not fin_txt:
            continue

        sh, sm = [int(x) for x in ini.split(":")]
        eh, em = [int(x) for x in fin_txt.split(":")]

        inicio_dt = datetime.combine(d, time(sh, sm))
        fin_dt = datetime.combine(d, time(eh, em))

        cur = inicio_dt
        while cur < fin_dt:
            fin_slot = cur + timedelta(minutes=int(intervalo_minutos))
            if fin_slot > fin_dt:
                break
            slots.append({
                "inicio": cur,
                "fin": fin_slot,
                "cupo_maximo": int(cupo_maximo),
                "cupo_usado": 0,
            })
            cur = fin_slot

    return slots


def plantilla_esta_en_uso(plantilla_id):
    cfg = get_config_semanal()
    dias = cfg.get("dias") or {}
    usados = []
    for k, v in dias.items():
        if not v:
            continue
        pid = v.get("plantilla_id")
        if pid and str(pid) == str(plantilla_id) and v.get("activo"):
            usados.append(k)
    return usados


def eliminar_plantilla(plantilla_id):
    if isinstance(plantilla_id, str):
        plantilla_id = ObjectId(plantilla_id)

    col = get_plantillas_collection()
    return col.delete_one({"_id": plantilla_id})
