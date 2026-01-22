import calendar
from functools import wraps
import os
import re
import shutil
from zoneinfo import ZoneInfo
from bson import ObjectId
from flask import abort, jsonify, render_template, redirect, send_file, url_for, request, session, flash
from pymongo import ReturnDocument

from app.services.alertas_clientes import obtener_clientes_por_vencer
from app.services.bloques import _get_blocks_for_date, _open_time_for_block, _slot_block_num, _turno_permite
from app.services.indicadores import _as_float_form, _build_kpi_and_chart
from . import web_bp
from app.services.user_service import get_users_collection, create_cajero, list_cajeros, reset_password_cliente, update_cajero, reset_password_cajero, delete_cajero, create_entrenador, list_entrenadores, update_entrenador, reset_password_entrenador, delete_entrenador
from app.extensions import bcrypt
from app.services.ventas_service import crear_venta, listar_ventas_por_cajero, resumen_ventas_hoy_por_cajero, get_ventas_collection
from datetime import date, datetime, timedelta, timezone, time as dtime
import time as pytime
import app.extensions as extensions
from app.services.horarios_semanales import (
    TZ_EC,
    eliminar_plantilla,
    get_config_semanal,
    listar_plantillas,
    get_plantilla_por_id,
    asignar_plantilla_a_dias,
    guardar_config_semanal,
    plantilla_esta_en_uso,
    resolver_bloques_del_dia,
    construir_slots_para_fecha,
    crear_plantilla,
    DIAS,
    
)
from app.services.reservas_service import (
    get_reservas_collection,
    get_horarios_collection,
    membresia_activa
)

from app.services.admin_config_service import (
     obtener_admin_por_username,
    actualizar_perfil_admin,
    cambiar_password_admin,
    obtener_configuracion_app,
    actualizar_configuracion_app,
    )

from app.services.clases_service import obtener_clases_hoy_entrenador

from app.services.entrenador_config_service import (
    obtener_entrenador_por_username,
    actualizar_perfil_entrenador,
    cambiar_password_entrenador,
)

from app.utils.pdf_tools import optimizar_pdf
from werkzeug.utils import secure_filename
from app.utils.image_tools import allowed_image, optimizar_imagen
from app.utils.media_tools import ffmpeg_disponible, optimizar_video_ffmpeg

from app.utils.horarios_tools import _week_id_from_date_str, _clamp_slot_restante

def _parse_date_yyyy_mm_dd(s: str):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.strip()) 
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def login_required(role=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("web.login"))
            if role and session.get("user_role") != role:
                flash("No tienes permiso para acceder a esta sección.", "danger")
                return redirect(url_for(f"web.{session.get('user_role')}_dashboard"))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


@web_bp.get("/")
def home():
    return render_template("home.html")


@web_bp.get("/login")
def login():
    return render_template("auth_login.html")


@web_bp.post("/login")
def login_post():
    username = request.form.get("username")
    password = request.form.get("password")

    user = get_users_collection().find_one({"username": username, "activo": True})

    if not user:
        flash("Usuario no encontrado", "danger")
        return redirect(url_for("web.login"))

    if not bcrypt.check_password_hash(user["password"], password):
        flash("Contraseña incorrecta", "danger")
        return redirect(url_for("web.login"))

    # ✅ PRIMERO: setear sesión
    session["user_id"] = str(user["_id"])
    session["username"] = user["username"]
    session["user_role"] = user["role"]

    # ✅ LUEGO: si debe cambiar contraseña, forzar
    if user.get("role") == "cliente" and user.get("must_change_password", False):
        session["force_pw_change"] = True
        return redirect(url_for("web.cliente_force_password"))

    # normal
    role_name = session.get("user_role")
    return redirect(url_for(f"web.{role_name}_dashboard"))



@web_bp.before_app_request
def enforce_password_change():
    
    if not session.get("username"):
        return

    if not session.get("force_pw_change"):
        return

    allowed = {
        "web.cliente_force_password",
        "web.cliente_force_password_post",
        "web.logout",
        "static",
    }

    # request.endpoint puede ser None
    if request.endpoint and request.endpoint not in allowed:
        return redirect(url_for("web.cliente_force_password"))

@web_bp.get("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("web.login"))


def _to_oid(v):
    if not v:
        return None
    if isinstance(v, ObjectId):
        return v
    try:
        return ObjectId(str(v))
    except Exception:
        return None
    
def _fecha_key(v):
    if not v:
        return ""
    try:
        if hasattr(v, "strftime"):
            return v.strftime("%Y-%m-%d")
        return str(v) 
    except Exception:
        return ""

# ADMINISTRADOR

@web_bp.get("/admin")
@login_required(role="admin")
def admin_dashboard():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    users = db["users"]
    clientes = db["clientes"]
    ventas = db["ventas"]
    noti_col = db["notificaciones"]  # ✅ NUEVO

    total_clientes = clientes.count_documents({})
    total_entrenadores = users.count_documents({"role": "entrenador"})
    total_cajeros = users.count_documents({"role": "cajero"})

    # --- tu lista actual ---
    clientes_por_vencer_raw = obtener_clientes_por_vencer(db, dias_objetivo=(2,1,0), limitar=300) or []

    # ✅ convertir esa lista a NOTIFICACIONES persistentes
    now_ec = datetime.now(TZ_EC)
    clientes_por_vencer = []

    for c in clientes_por_vencer_raw:
        # AJUSTE: tu función normalmente trae cliente_id; si no, intenta _id
        cid = _to_oid(c.get("cliente_id") or c.get("_id") or c.get("idCliente"))
        if not cid:
            continue

        fh_key = _fecha_key(c.get("fecha_hasta") or c.get("hasta") or c.get("vence"))
        # clave estable (un aviso por cliente+fecha_hasta)
        key = {"tipo": "renovacion", "cliente_id": cid, "fecha_hasta": fh_key}

        doc = noti_col.find_one_and_update(
            key,
            {
                "$setOnInsert": {
                    "tipo": "renovacion",
                    "cliente_id": cid,
                    "fecha_hasta": fh_key,
                    "creado_at": now_ec,
                    "visto": False,
                },
                "$set": {
                    "updated_at": now_ec,
                    # snapshot para mostrar en modal aunque cambien datos
                    "payload": {
                        "nombre": c.get("nombre"),
                        "identificacion": c.get("identificacion"),
                        "telefono": c.get("telefono"),
                        "email": c.get("email"),
                        "dias_restantes": c.get("dias_restantes"),
                        "no_renovo": bool(c.get("no_renovo")),
                        "fecha_hasta": fh_key,
                    }
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

        # ✅ Solo mandar al template las NO vistas (esto hace que “desaparezcan”)
        if not doc.get("visto", False):
            c["noti_id"] = str(doc["_id"])   # ✅ ID de la notificación
            clientes_por_vencer.append(c)

    # --- tu lógica de ventas hoy (sin tocar) ---
    ahora = datetime.now(timezone.utc)
    inicio = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    fin = ahora.replace(hour=23, minute=59, second=59, microsecond=999000)

    ventas_hoy = ventas.count_documents({"fecha": {"$gte": inicio, "$lte": fin}})

    pipeline = [
        {"$match": {"fecha": {"$gte": inicio, "$lte": fin}}},
        {"$sort": {"fecha": -1}},
        {"$limit": 10},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "fecha": 1,
            "vendedor": 1,
            "membresia": 1,
            "cliente_nombre": {"$ifNull": ["$cliente.nombre", ""]},
            "cliente_apellido": {"$ifNull": ["$cliente.apellido", ""]},
            "cliente_identificacion": {"$ifNull": ["$cliente.identificacion", ""]},
        }},
    ]
    ultimas_ventas = list(ventas.aggregate(pipeline))

    return render_template(
        "dashboard_admin.html",
        total_clientes=total_clientes,
        show_publicidad=True,
        total_entrenadores=total_entrenadores,
        total_cajeros=total_cajeros,
        clientes_por_vencer=clientes_por_vencer,  # ✅ ya filtrado: solo NO vistos
        ventas_hoy=ventas_hoy,
        ultimas_ventas=ultimas_ventas,
    )
    


@web_bp.post("/admin/notificaciones/renovacion/<noti_id>/visto")
@login_required(role="admin")
def admin_noti_renovacion_visto(noti_id):
    db = extensions.mongo_db
    noti_col = db["notificaciones"]

    try:
        oid = ObjectId(noti_id)
    except Exception:
        return jsonify(ok=False, error="ID inválido"), 400

    now_ec = datetime.now(TZ_EC)
    admin_id = _to_oid(session.get("user_id"))

    res = noti_col.update_one(
        {"_id": oid, "tipo": "renovacion"},
        {"$set": {"visto": True, "visto_at": now_ec, "visto_por": admin_id}},
    )

    if res.matched_count == 0:
        return jsonify(ok=False, error="Notificación no encontrada"), 404

    return jsonify(ok=True)

@web_bp.get("/admin/ventas")
@login_required(role="admin")
def admin_ventas_listado():
    db = extensions.mongo_db
    ventas_col = db["ventas"]
    users = db["users"]
    cajeros = list(users.find({"role": "cajero"}, {"username": 1}).sort("username", 1))

    q = (request.args.get("q") or "").strip()
    desde = (request.args.get("desde") or "").strip()
    hasta = (request.args.get("hasta") or "").strip()

    page = request.args.get("page", "1")
    try:
        page = max(1, int(page))
    except ValueError:
        page = 1

    limit = 20
    skip = (page - 1) * limit

    dt_desde = _parse_date_yyyy_mm_dd(desde)
    dt_hasta = _parse_date_yyyy_mm_dd(hasta)

    match = {}
    if dt_desde or dt_hasta:
        rango = {}
        if dt_desde:
            rango["$gte"] = dt_desde.replace(hour=0, minute=0, second=0, microsecond=0)
        if dt_hasta:
            rango["$lte"] = dt_hasta.replace(hour=23, minute=59, second=59, microsecond=999000)
        match["fecha"] = rango

    pipeline_base = []
    if match:
        pipeline_base.append({"$match": match})

    pipeline_base += [
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
    ]

    if q:
        pipeline_base.append({
            "$match": {
                "$or": [
                    {"cliente.nombre": {"$regex": q, "$options": "i"}},
                    {"cliente.apellido": {"$regex": q, "$options": "i"}},
                    {"cliente.identificacion": {"$regex": q, "$options": "i"}},
                ]
            }
        })

    # total para paginación
    total_pipe = pipeline_base + [{"$count": "total"}]
    total_res = list(ventas_col.aggregate(total_pipe))
    total = total_res[0]["total"] if total_res else 0
    total_pages = (total + limit - 1) // limit

    # data
    pipeline_data = pipeline_base + [
        {"$sort": {"fecha": -1}},
        {"$skip": skip},
        {"$limit": limit},
        {"$project": {
            "_id": 1,
            "fecha": 1,
            "vendedor": 1,
            "membresia": 1,
            "cliente_nombre": {"$ifNull": ["$cliente.nombre", ""]},
            "cliente_apellido": {"$ifNull": ["$cliente.apellido", ""]},
            "cliente_identificacion": {"$ifNull": ["$cliente.identificacion", ""]},
            "cliente_telefono": {"$ifNull": ["$cliente.telefono", ""]},
        }},
    ]

    rows = list(ventas_col.aggregate(pipeline_data))

    return render_template(
        "admin_ventas.html",
        ventas=rows,
        cajeros=cajeros,
        q=q, desde=desde, hasta=hasta,
        page=page, total_pages=total_pages, total=total,
    )
    
@web_bp.get("/admin/ventas/<venta_id>/edit")
@login_required(role="admin")
def admin_venta_edit(venta_id):
    db = extensions.mongo_db
    ventas = db["ventas"]
    clientes = db["clientes"]
    users = db["users"]

    try:
        oid = ObjectId(venta_id)
    except Exception:
        flash("ID de venta inválido.", "danger")
        return redirect(url_for("web.admin_ventas_listado"))

    venta = ventas.find_one({"_id": oid, "deleted_at": {"$exists": False}})
    if not venta:
        flash("Venta no encontrada.", "danger")
        return redirect(url_for("web.admin_ventas_listado"))

    cliente = clientes.find_one({"_id": venta.get("cliente_id")}) if venta.get("cliente_id") else None

    cajeros = list(users.find({"role": "cajero"}, {"username": 1}).sort("username", 1))

    # valores para inputs type="date"
    venta_view = {
        "_id": str(venta["_id"]),
        "fecha": _parse_date_yyyy_mm_dd(venta.get("fecha")),
        "vendedor": venta.get("vendedor", ""),
        "meses": (venta.get("membresia") or {}).get("meses", ""),
        "fecha_desde": _parse_date_yyyy_mm_dd((venta.get("membresia") or {}).get("fecha_desde")),
        "fecha_hasta": _parse_date_yyyy_mm_dd((venta.get("membresia") or {}).get("fecha_hasta")),
        "cliente_identificacion": (cliente or {}).get("identificacion", ""),
        "cliente_nombre": (cliente or {}).get("nombre", ""),
        "cliente_apellido": (cliente or {}).get("apellido", ""),
    }

    return render_template("admin_venta_edit.html", venta=venta_view, cajeros=cajeros)

@web_bp.post("/admin/ventas/<venta_id>/edit")
@login_required(role="admin")
def admin_venta_edit_post(venta_id):
    db = extensions.mongo_db
    ventas = db["ventas"]
    clientes = db["clientes"]
    users = db["users"]

    try:
        oid = ObjectId(venta_id)
    except Exception:
        flash("ID de venta inválido.", "danger")
        return redirect(url_for("web.admin_ventas_listado"))

    venta = ventas.find_one({"_id": oid, "deleted_at": {"$exists": False}})
    if not venta:
        flash("Venta no encontrada.", "danger")
        return redirect(url_for("web.admin_ventas_listado"))

    cliente_ident = (request.form.get("cliente_identificacion") or "").strip()
    vendedor = (request.form.get("vendedor") or "").strip()
    fecha = _parse_date_yyyy_mm_dd((request.form.get("fecha") or "").strip())

    meses_raw = (request.form.get("meses") or "").strip()
    f_desde = _parse_date_yyyy_mm_dd((request.form.get("fecha_desde") or "").strip())
    f_hasta = _parse_date_yyyy_mm_dd((request.form.get("fecha_hasta") or "").strip())   
    # Validaciones básicas
    if not cliente_ident:
        flash("La identificación del cliente es obligatoria.", "danger")
        return redirect(url_for("web.admin_venta_edit", venta_id=venta_id))

    cliente = clientes.find_one({"identificacion": cliente_ident})
    if not cliente:
        flash("No existe un cliente con esa identificación.", "danger")
        return redirect(url_for("web.admin_venta_edit", venta_id=venta_id))

    if vendedor:
        cajero = users.find_one({"username": vendedor, "role": "cajero"})
        if not cajero:
            flash("Vendedor inválido (debe ser un usuario cajero).", "danger")
            return redirect(url_for("web.admin_venta_edit", venta_id=venta_id))

    meses = None
    if meses_raw != "":
        try:
            meses = int(meses_raw)
            if meses < 0:
                raise ValueError()
        except Exception:
            flash("Meses inválido.", "danger")
            return redirect(url_for("web.admin_venta_edit", venta_id=venta_id))

    # Si te obligas a tener desde/hasta:
    if f_desde and f_hasta and f_desde > f_hasta:
        flash("La fecha 'Desde' no puede ser mayor que 'Hasta'.", "danger")
        return redirect(url_for("web.admin_venta_edit", venta_id=venta_id))

    update = {
        "cliente_id": cliente["_id"],
        "vendedor": vendedor,
    }

    if fecha:
        update["fecha"] = fecha

    update["membresia"] = {
        "meses": meses,
        "fecha_desde": f_desde,
        "fecha_hasta": f_hasta,
    }

    # auditoría
    update["updated_at"] = datetime.now(timezone.utc)
    update["updated_by"] = session.get("username")

    ventas.update_one({"_id": oid}, {"$set": update})

    flash("Venta actualizada.", "success")
    return redirect(url_for("web.admin_ventas_listado"))


@web_bp.post("/admin/ventas/<venta_id>/delete")
@login_required(role="admin")
def admin_venta_delete(venta_id):
    db = extensions.mongo_db
    ventas = db["ventas"]

    try:
        oid = ObjectId(venta_id)
    except Exception:
        flash("ID de venta inválido.", "danger")
        return redirect(url_for("web.admin_ventas_listado"))

    res = ventas.delete_one({"_id": oid})

    if res.deleted_count == 0:
        flash("Venta no encontrada o ya eliminada.", "warning")
    else:
        flash("Venta eliminada.", "success")

    return redirect(url_for("web.admin_ventas_listado"))




#ADMIN CONFIGURACION
@web_bp.get("/admin/configuracion")
@login_required(role="admin")
def admin_configuracion():
    admin = obtener_admin_por_username(session.get("username"))
    if not admin:
        flash("No se encontró el administrador en la base.", "danger")
        return redirect(url_for("web.logout"))

    configuracion = obtener_configuracion_app()
    return render_template("admin_configuracion.html", admin=admin, settings=configuracion)


@web_bp.post("/admin/configuracion/perfil")
@login_required(role="admin")
def admin_configuracion_perfil():
    admin = obtener_admin_por_username(session.get("username"))
    if not admin:
        flash("No se encontró el administrador.", "danger")
        return redirect(url_for("web.logout"))

    username = request.form.get("username", "").strip()
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip()
    telefono = request.form.get("telefono", "").strip()

    try:
        actualizado = actualizar_perfil_admin(
            str(admin["_id"]),
            username=username,
            nombre=nombre,
            email=email,
            telefono=telefono,
        )
        session["username"] = actualizado["username"]
        flash("Perfil actualizado correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_configuracion"))


@web_bp.post("/admin/configuracion/password")
@login_required(role="admin")
def admin_configuracion_password():
    admin = obtener_admin_por_username(session.get("username"))
    if not admin:
        flash("No se encontró el administrador.", "danger")
        return redirect(url_for("web.logout"))

    password_actual = request.form.get("current_password", "")
    password_nuevo = request.form.get("new_password", "")
    password_confirmar = request.form.get("confirm_password", "")

    if password_nuevo != password_confirmar:
        flash("La confirmación no coincide.", "danger")
        return redirect(url_for("web.admin_configuracion"))

    try:
        cambiar_password_admin(str(admin["_id"]), password_actual, password_nuevo)
        flash("Contraseña actualizada correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_configuracion"))


@web_bp.post("/admin/configuracion/sistema")
@login_required(role="admin")
def admin_configuracion_sistema():
    gym_nombre = request.form.get("gym_nombre", "").strip()
    gym_direccion = request.form.get("gym_direccion", "").strip()
    gym_telefono = request.form.get("gym_telefono", "").strip()
    moneda = request.form.get("moneda", "USD").strip()

    actualizar_configuracion_app(
        gym_nombre=gym_nombre,
        gym_direccion=gym_direccion,
        gym_telefono=gym_telefono,
        moneda=moneda
    )
    flash("Configuración del sistema actualizada.", "success")
    return redirect(url_for("web.admin_configuracion"))

@web_bp.get("/admin/no-asistire-manana")
@login_required(role="admin")
def admin_no_asistire_manana():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    reservas_col = db["reservas"]
    clientes_col = db["clientes"]
    users_col = db["users"]

    TZ_EC = ZoneInfo("America/Guayaquil")
    manana = datetime.now(TZ_EC).date() + timedelta(days=1)
    manana_key = manana.isoformat()

    pipeline = [
        {"$match": {
            "fecha": manana_key,
            "no_asistire": True,
            "estado": {"$ne": "cancelada"},
            "cancelada": {"$ne": True},

            # ✅ SOLO NO VISTOS
            "no_asistire_visto_admin": {"$ne": True},
        }},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cli"
        }},
        {"$unwind": {"path": "$cli", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {
            "from": "users",
            "localField": "entrenador_id",
            "foreignField": "_id",
            "as": "ent"
        }},
        {"$unwind": {"path": "$ent", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "_id": 1,
            "fecha": 1,
            "slot_id": 1,
            "no_asistire_at": 1,
            "no_asistire_motivo": 1,
            "estado": 1,
            "cliente_nombre": {"$ifNull": ["$cli.nombre", ""]},
            "cliente_apellido": {"$ifNull": ["$cli.apellido", ""]},
            "cliente_identificacion": {"$ifNull": ["$cli.identificacion", ""]},
            "cliente_telefono": {"$ifNull": ["$cli.telefono", ""]},
            "entrenador": {"$ifNull": ["$ent.username", "-"]},
        }},
        {"$sort": {"no_asistire_at": -1}}
    ]

    rows = list(reservas_col.aggregate(pipeline))

    # opcional: calcula hora desde slot_id "YYYY-MM-DD|HH:MM"
    for r in rows:
        sid = r.get("slot_id") or ""
        r["hora"] = sid.split("|", 1)[1] if ("|" in sid) else ""

    return render_template(
        "admin_no_asistir.html",
        manana_key=manana_key,
        rows=rows
    )

@web_bp.post("/admin/no-asistire/<reserva_id>/visto")
@login_required(role="admin")
def admin_marcar_no_asistire_visto(reserva_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    reservas_col = db["reservas"]

    try:
        rid = ObjectId(reserva_id)
    except Exception:
        flash("Reserva inválida.", "danger")
        return redirect(url_for("web.admin_no_asistire_manana"))

    # admin logueado
    admin_id = session.get("user_id")
    admin_oid = None
    try:
        if admin_id:
            admin_oid = ObjectId(admin_id)
    except Exception:
        admin_oid = None

    TZ_EC = ZoneInfo("America/Guayaquil")
    now_ec = datetime.now(TZ_EC)

    r = reservas_col.find_one({"_id": rid}, {"no_asistire": 1})
    if not r:
        flash("No se encontró la reserva.", "danger")
        return redirect(url_for("web.admin_no_asistire_manana"))

    if r.get("no_asistire") is not True:
        flash("Esta reserva no está marcada como 'no asistiré'.", "warning")
        return redirect(url_for("web.admin_no_asistire_manana"))

    reservas_col.update_one(
        {"_id": rid},
        {"$set": {
            "no_asistire_visto_admin": True,
            "no_asistire_visto_at": now_ec,
            **({"no_asistire_visto_por": admin_oid} if admin_oid else {})
        }}
    )

    flash("Marcado como visto.", "success")
    return redirect(url_for("web.admin_no_asistire_manana"))

# ADMIN CAJEROS
@web_bp.get("/admin/cajeros")
@login_required(role="admin")
def admin_cajeros():
    cajeros = list_cajeros()
    return render_template("admin_cajeros.html", cajeros=cajeros)


@web_bp.post("/admin/cajeros")
@login_required(role="admin")
def admin_cajeros_post():
    username = request.form.get("username")
    nombre = request.form.get("nombre")
    apellido = request.form.get("apellido")
    email = request.form.get("email")
    telefono = request.form.get("telefono")
    password = request.form.get("password")

    if not username or not password:
        flash("Usuario y contraseña son obligatorios.", "danger")
        return redirect(url_for("web.admin_cajeros"))

    try:
        create_cajero(
            username=username,
            password=password,
            nombre=nombre,
            apellido=apellido,
            email=email,
            telefono=telefono
        )
        flash(f"Cajero '{username}' creado correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))

# EDITAR CAJERO ADMIN

@web_bp.post("/admin/cajeros/<cajero_id>/edit")
@login_required(role="admin")
def admin_cajeros_edit(cajero_id):
    username = request.form.get("username")
    nombre = request.form.get("nombre")
    apellido = request.form.get("apellido")
    email = request.form.get("email")
    telefono = request.form.get("telefono")

    try:
        update_cajero(cajero_id, username=username, nombre=nombre, apellido=apellido, email=email, telefono=telefono)
        flash("Cajero actualizado.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))

# RESET PASSWORD CAJERO ADMIN
@web_bp.post("/admin/cajeros/<cajero_id>/reset-password")
@login_required(role="admin")
def admin_cajeros_reset_password(cajero_id):
    new_password = request.form.get("new_password")
    if not new_password:
        flash("La nueva contraseña es obligatoria.", "danger")
        return redirect(url_for("web.admin_cajeros"))

    try:
        reset_password_cajero(cajero_id, new_password)
        flash("Contraseña actualizada.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))


# ELIMINAR CAJERO ADMIN

@web_bp.post("/admin/cajeros/<cajero_id>/delete")
@login_required(role="admin")
def admin_cajeros_delete(cajero_id):
    try:
        delete_cajero(cajero_id)
        flash("Cajero eliminado.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_cajeros"))




# ADMIN USUARIOS

@web_bp.get("/admin/usuarios")
@login_required(role="admin")
def admin_usuarios():
    db = extensions.mongo_db
    users_col = db["users"]
    clientes_col = db["clientes"]

    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()

    filtro = {}


    if role:
        filtro["role"] = role

    if q:
        regex = {"$regex": q, "$options": "i"}

        clientes_ids = []
        clientes_cursor = clientes_col.find(
            {"$or": [
                {"nombre": regex},
                {"identificacion": regex},
                {"email": regex},
                {"apellido": regex},
                {"telefono": regex},
            ]},
            {"_id": 1}
        )
        for c in clientes_cursor:
            clientes_ids.append(c["_id"])


        or_conditions = [
            {"username": regex},
            {"nombre": regex},
        ]

        if clientes_ids:
            or_conditions.append({
                "$and": [
                    {"role": "cliente"},
                    {"$or": [
                        {"_id": {"$in": clientes_ids}},
                        {"cliente_id": {"$in": clientes_ids}},
                    ]}
                ]
            })

        if role == "cliente":
            filtro["$or"] = [
                {"username": regex},
                {"nombre": regex},
                {"apellido": regex},
                {"_id": {"$in": clientes_ids}} if clientes_ids else {"_id": None},
                {"cliente_id": {"$in": clientes_ids}} if clientes_ids else {"cliente_id": None},
            ]
        else:
            filtro["$or"] = or_conditions

    usuarios = list(users_col.find(filtro).sort("username", 1))


    cliente_ids_tabla = []
    for u in usuarios:
        if u.get("role") == "cliente":
            cid = u.get("cliente_id") or u.get("_id")
            try:
                cid = ObjectId(str(cid))
            except Exception:
                cid = None
            if cid:
                cliente_ids_tabla.append(cid)

    clientes_map = {}
    if cliente_ids_tabla:
        for c in clientes_col.find({"_id": {"$in": cliente_ids_tabla}}, {"nombre": 1, "apellido": 1}):
            nom = (c.get("nombre") or "").strip()
            ape = (c.get("apellido") or "").strip()
            full = (nom + " " + ape).strip() or "-"
            clientes_map[str(c["_id"])] = full


    for u in usuarios:
        if u.get("role") == "cliente":
            cid = u.get("cliente_id") or u.get("_id")
            u["nombre_mostrar"] = clientes_map.get(str(cid), "-")
        else:
            u["nombre_mostrar"] = u.get("nombre") or "-"
            nom = (u.get("nombre") or "").strip()
            ape = (u.get("apellido") or "").strip()
            u["nombre_mostrar"] = (nom + " " + ape).strip() or "-"


    return render_template("admin_usuarios.html", usuarios=usuarios, q=q, role=role)


@web_bp.get("/admin/usuarios/<user_id>")
@login_required(role="admin")
def admin_usuario_editar(user_id):
    db = extensions.mongo_db
    users_col = db["users"]
    clientes_col = db["clientes"]

    try:
        oid = ObjectId(str(user_id))
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    u = users_col.find_one({"_id": oid})
    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    cliente = None
    if u.get("role") == "cliente":
        cid = u.get("cliente_id")

        if not cid:
            cid = u["_id"]

        try:
            cid = ObjectId(str(cid))
        except Exception:
            cid = None

        if cid:
            cliente = clientes_col.find_one({"_id": cid})

    return render_template("admin_usuarios_editar.html", u=u, cliente=cliente)



@web_bp.post("/admin/usuarios/<user_id>/guardar")
@login_required(role="admin")
def admin_usuario_guardar(user_id):
    db = extensions.mongo_db
    users_col = db["users"]
    clientes_col = db["clientes"]

    try:
        oid = ObjectId(str(user_id))
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    u = users_col.find_one({"_id": oid})
    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    username = (request.form.get("username") or "").strip()
    role = (request.form.get("role") or "").strip()
    new_password = (request.form.get("new_password") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    apellido = (request.form.get("apellido") or "").strip() or None
    telefono = (request.form.get("telefono") or "").strip() or None


    nombre = (request.form.get("nombre") or "").strip()
    cliente_nombre = (request.form.get("cliente_nombre") or "").strip()
    cliente_apellido = (request.form.get("cliente_apellido") or "").strip() or None
    cliente_email = (request.form.get("cliente_email") or "").strip() or None
    cliente_telefono = (request.form.get("cliente_telefono") or "").strip() or None


    try:
        if not username:
            raise ValueError("Username es obligatorio.")
        if role not in ("admin", "cajero", "entrenador", "cliente"):
            raise ValueError("Rol inválido.")

        if username != u.get("username"):
            if users_col.find_one({"username": username, "_id": {"$ne": oid}}):
                raise ValueError("Ese username ya está en uso.")

        update_user = {"username": username, "role": role, "email": email, "apellido": apellido, "telefono": telefono}

        if new_password:
            if len(new_password) < 6:
                raise ValueError("La contraseña debe tener al menos 6 caracteres.")
            update_user["password"] = bcrypt.generate_password_hash(new_password).decode("utf-8")
            update_user["must_change_password"] = False  

        if role != "cliente":
            update_user["nombre"] = nombre
            update_user["apellido"] = apellido
            update_user["correo"] = email     # o "email" si prefieres, pero usa 1 solo nombre
            update_user["telefono"] = telefono
            

        users_col.update_one({"_id": oid}, {"$set": update_user})

        if role == "cliente":
            if not cliente_nombre:
                cliente_nombre = nombre

            cid = u.get("cliente_id") or oid
            try:
                cid = ObjectId(str(cid))
            except Exception:
                cid = None

            if cid and cliente_nombre:
                clientes_col.update_one(
                    {"_id": cid},
                    {"$set": {
                        "nombre": cliente_nombre,
                        "apellido": cliente_apellido,
                        "email": cliente_email,
                        "telefono": cliente_telefono,
                    }},
                    upsert=True
                )

        flash("Usuario actualizado correctamente.", "success")

    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_usuarios"))


@web_bp.post("/admin/usuarios/<user_id>/toggle-activo")
@login_required(role="admin")
def admin_usuario_toggle_activo(user_id):
    db = extensions.mongo_db
    users_col = db["users"]

    try:
        oid = ObjectId(str(user_id))
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    u = users_col.find_one({"_id": oid})
    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.admin_usuarios"))

    if session.get("username") == u.get("username"):
        flash("No puedes desactivarte a ti mismo.", "warning")
        return redirect(url_for("web.admin_usuarios"))

    nuevo = not bool(u.get("activo", True))
    users_col.update_one({"_id": oid}, {"$set": {"activo": nuevo}})

    flash(f"Usuario {'activado' if nuevo else 'desactivado'} correctamente.", "success")
    return redirect(url_for("web.admin_usuarios"))


# ADMIN ENTRENADORES
@web_bp.get("/admin/entrenadores")
@login_required(role="admin")
def admin_entrenadores():
    entrenadores = list_entrenadores()
    return render_template("admin_entrenadores.html", entrenadores=entrenadores)


@web_bp.post("/admin/entrenadores")
@login_required(role="admin")
def admin_entrenadores_post():
    username = (request.form.get("username") or "").strip()
    nombre = (request.form.get("nombre") or "").strip() or None
    password = (request.form.get("password") or "").strip()
    apellido = (request.form.get("apellido") or "").strip() or None
    email = (request.form.get("email") or "").strip() or None
    telefono = (request.form.get("telefono") or "").strip() or None


    try:
        if not username or not password:
            raise ValueError("Usuario y contraseña son obligatorios.")
        if len(password) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres.")
        create_entrenador(
            username,
            password,
            nombre=nombre,
            apellido=apellido,
            email=email,
            telefono=telefono
        )

        flash("Entrenador creado correctamente.", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_entrenadores"))


@web_bp.post("/admin/entrenadores/editar/<entrenador_id>")
@login_required(role="admin")
def admin_entrenadores_edit(entrenador_id):
    username = (request.form.get("username") or "").strip()
    nombre = (request.form.get("nombre") or "").strip() or None
    apellido = (request.form.get("apellido") or "").strip() or None
    email = (request.form.get("email") or "").strip() or None
    telefono = (request.form.get("telefono") or "").strip() or None
    try:
        if not username:
            raise ValueError("Usuario es obligatorio.")
        update_entrenador(entrenador_id, username=username, nombre=nombre, apellido=apellido, email=email, telefono=telefono)
        flash("Entrenador actualizado correctamente.", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_entrenadores"))


@web_bp.post("/admin/entrenadores/reset-password/<entrenador_id>")
@login_required(role="admin")
def admin_entrenadores_reset_password(entrenador_id):
    new_password = (request.form.get("new_password") or "").strip()

    try:
        reset_password_entrenador(entrenador_id, new_password)
        flash("Contraseña actualizada correctamente.", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_entrenadores"))


@web_bp.post("/admin/entrenadores/eliminar/<entrenador_id>")
@login_required(role="admin")
def admin_entrenadores_delete(entrenador_id):
    try:
        delete_entrenador(entrenador_id)
        flash("Entrenador eliminado correctamente.", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_entrenadores"))



#ADMIN CLIENTES



@web_bp.get("/admin/clientes")
@login_required(role="admin")
def admin_clientes():
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    q = (request.args.get("q") or "").strip()

    match = {}
    if q:
        match["$or"] = [
            {"nombre": {"$regex": q, "$options": "i"}},
            {"identificacion": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"apellido": {"$regex": q, "$options": "i"}},
            {"telefono": {"$regex": q, "$options": "i"}},
            {"fecha_nacimiento": {"$regex": q, "$options": "i"}},
        ]


    pipeline = [
        {"$match": match},

        {"$lookup": {
            "from": "ventas",
            "let": {"cid": "$_id"},
            "pipeline": [
                {"$match": {"$expr": {"$eq": ["$cliente_id", "$$cid"]}}},
                {"$sort": {"fecha": -1}},
                {"$limit": 1},
                {"$project": {"membresia": 1, "fecha": 1}}
            ],
            "as": "ultima_venta"
        }},

        {"$addFields": {
            "ultima_venta": {"$arrayElemAt": ["$ultima_venta", 0]}
        }},

        {"$addFields": {
            "fecha_hasta": "$ultima_venta.membresia.fecha_hasta"
        }},
        {"$addFields": {
            "fecha_nacimiento_str": {
                "$cond": [
                    {"$and": [
                        {"$ne": ["$fecha_nacimiento", None]},
                        {"$eq": [{"$type": "$fecha_nacimiento"}, "date"]}
                    ]},
                    {"$dateToString": {"format": "%d/%m/%Y", "date": "$fecha_nacimiento"}},
                    {
                        "$cond": [
                            {"$and": [
                                {"$ne": ["$fecha_nacimiento", None]},
                                {"$eq": [{"$type": "$fecha_nacimiento"}, "string"]}
                            ]},
                            "$fecha_nacimiento",
                            ""
                        ]
                    }
                ]
            }
        }},

    ]

    clientes = list(clientes_col.aggregate(pipeline))
    return render_template("admin_clientes.html", clientes=clientes, q=q)


@web_bp.post("/admin/clientes/editar/<cliente_id>")
@login_required(role="admin")
def admin_clientes_editar(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    try:
        oid = ObjectId(str(cliente_id))
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.admin_clientes"))

    nombre = (request.form.get("nombre") or "").strip()
    identificacion = (request.form.get("identificacion") or "").strip()
    email = (request.form.get("email") or "").strip() or None
    telefono = (request.form.get("telefono") or "").strip() or None
    apellido = (request.form.get("apellido") or "").strip() or None
    fecha_nacimiento = (request.form.get("fecha_nacimiento") or "").strip() or None

    if not nombre or not identificacion:
        flash("Nombre e identificación son obligatorios.", "danger")
        return redirect(url_for("web.admin_clientes"))

    clientes_col.update_one(
        {"_id": oid},
        {"$set": {
            "nombre": nombre,
            "apellido": apellido,
            "identificacion": identificacion,
            "email": email,
            "telefono": telefono,
            "fecha_nacimiento": fecha_nacimiento,
        }}
    )

    flash("Cliente actualizado.", "success")
    return redirect(url_for("web.admin_clientes"))







# VENTA 

@web_bp.get("/admin/facturacion/nueva")
@login_required()  
def facturacion_nueva():
    return render_template("facturacion.html")


@web_bp.post("/admin/facturacion/nueva")
@login_required()
def facturacion_nueva_post():
    identificacion = request.form.get("identificacion")
    nombre = request.form.get("nombre")
    email = request.form.get("email") or None
    apellido = (request.form.get("apellido") or "").strip() or None
    telefono = request.form.get("telefono") or None
    fecha_nacimiento_raw = request.form.get("fecha_nacimiento") or None


    meses_raw = request.form.get("meses") or "1"
    fecha_desde_raw = request.form.get("fecha_desde")
    fecha_hasta_raw = request.form.get("fecha_hasta")

    if not identificacion or not nombre:
        flash("Identificación y nombre del cliente son obligatorios.", "danger")
        return redirect(url_for("web.facturacion_nueva"))
    
    fecha_nacimiento = None
    if fecha_nacimiento_raw:
        try:
            fecha_nacimiento = datetime.strptime(fecha_nacimiento_raw, "%Y-%m-%d")
        except ValueError:
            flash("Fecha de nacimiento inválida.", "danger")
            return redirect(url_for("web.facturacion_nueva"))


    try:
        meses = int(meses_raw)
        if meses < 1 or meses > 12:
            raise ValueError()
    except ValueError:
        flash("Meses inválidos (debe ser 1 a 12).", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    try:
        if fecha_desde_raw:
            fecha_desde_date = datetime.strptime(fecha_desde_raw, "%Y-%m-%d").date()
        else:
            fecha_desde_date = date.today()
    except ValueError:
        flash("Fecha desde inválida.", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    try:
        if fecha_hasta_raw:
            fecha_hasta_date = datetime.strptime(fecha_hasta_raw, "%Y-%m-%d").date()
        else:
            fecha_hasta_date = fecha_desde_date + timedelta(days=meses * 30)
    except ValueError:
        flash("Fecha hasta inválida.", "danger")
        return redirect(url_for("web.facturacion_nueva"))

    fecha_desde_dt = datetime.combine(fecha_desde_date, dtime.min)
    fecha_hasta_dt = datetime.combine(fecha_hasta_date, dtime.min)


    cliente_data = {
        "identificacion": identificacion,
        "nombre": nombre,
        "apellido": apellido,
        "email": email,
        "telefono": telefono,
        "fecha_nacimiento": fecha_nacimiento,
    }

    membresia = {
        "tipo": "membresia",
        "meses": meses,
        "fecha_desde": fecha_desde_dt,  
        "fecha_hasta": fecha_hasta_dt,  
    }

    vendedor_username = session.get("username")

    venta = crear_venta(cliente_data, membresia, vendedor_username)

    return render_template(
        "venta_lista.html",
        venta=venta,
        credenciales={
            "username": (venta.get("cliente_username") or ""),
            "password": (venta.get("_generated_password") or ""),
        }
    )
    
    
# ADMIN PUBLICIDAD


@web_bp.get("/admin/publicidad")
@login_required(role="admin")
def admin_publicidad():
    db = extensions.mongo_db
    pub_col = db["publicidades"]

    pubs = list(pub_col.find({}).sort("creado", -1).limit(30))

    return render_template(
        "admin_publicidad.html",
        pubs=pubs,
        active="admin_publicidad"
    )


@web_bp.post("/admin/publicidad/subir")
@login_required(role="admin")
def admin_publicidad_subir():
    db = extensions.mongo_db
    pub_col = db["publicidades"]
    titulo = (request.form.get("titulo") or "").strip()

    # ✅ ahora se llama "archivo" (imagen o video)
    f = request.files.get("archivo")
    if not f or not f.filename:
        flash("No se subió ningún archivo.", "warning")
        return redirect(url_for("web.admin_publicidad"))

    filename = secure_filename(f.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    allowed_img = {"jpg", "jpeg", "png", "webp"}
    allowed_vid = {"mp4", "mov", "m4v", "webm", "avi"}

    if ext in allowed_img:
        kind = "image"
    elif ext in allowed_vid:
        kind = "video"
    else:
        flash("Formato no permitido. Usa imagen (JPG/PNG/WEBP) o video (MP4/MOV/WEBM).", "danger")
        return redirect(url_for("web.admin_publicidad"))

    base_dir = os.path.join(os.getcwd(), "uploads", "publicidad")
    tmp_dir  = os.path.join(base_dir, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    ts_tmp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{filename}")

    # guardar temporal
    f.save(tmp_path)
    try:
        f.close()
    except Exception:
        pass

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # ✅ nombre final según tipo
    if kind == "video":
        final_name = f"pub_{ts}.mp4"  # siempre mp4 optimizado
    else:
        final_name = f"pub_{ts}.jpg"  # siempre jpg optimizado

    final_path = os.path.join(base_dir, final_name)
    final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}__{final_name}")

    try:
        if kind == "video":
            # ✅ si no hay ffmpeg (Windows), no revienta: guarda sin optimizar
            if ffmpeg_disponible():
                optimizar_video_ffmpeg(tmp_path, final_tmp_path)
            else:
                replace_with_retry(tmp_path, final_tmp_path)
        else:
            # ✅ optimiza imagen
            optimizar_imagen(tmp_path, final_tmp_path, max_side=1600, quality=82)

        replace_with_retry(final_tmp_path, final_path)

    except Exception:
        # último recurso: guardar el original tal cual
        try:
            replace_with_retry(tmp_path, final_path)
        except Exception:
            safe_delete_or_quarantine(tmp_path)
            safe_delete_or_quarantine(final_tmp_path)
            flash("No se pudo guardar la publicidad.", "danger")
            return redirect(url_for("web.admin_publicidad"))

    finally:
        safe_delete_or_quarantine(tmp_path)
        safe_delete_or_quarantine(final_tmp_path)

    if not os.path.exists(final_path):
        flash("No se pudo guardar la publicidad.", "danger")
        return redirect(url_for("web.admin_publicidad"))

    file_size = os.path.getsize(final_path)
    rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

    pub_col.insert_one({
        "titulo": titulo or "Publicidad",
        "kind": kind,                 # ✅ image / video
        "filename": final_name,
        "rel_path": rel_path,
        "bytes": int(file_size),
        "activo": False,
        "creado": datetime.now(timezone.utc),
    })

    if kind == "video" and not ffmpeg_disponible():
        flash("Publicidad subida. (Sin FFmpeg: el video se guardó sin optimizar).", "warning")
    else:
        flash("Publicidad subida (optimizada). Ahora puedes activarla.", "success")

    return redirect(url_for("web.admin_publicidad"))


@web_bp.post("/admin/publicidad/<pub_id>/activar")
@login_required(role="admin")
def admin_publicidad_activar(pub_id):
    db = extensions.mongo_db
    pub_col = db["publicidades"]

    try:
        pid = ObjectId(pub_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.admin_publicidad"))

    pub_col.update_many({}, {"$set": {"activo": False}})
    pub_col.update_one({"_id": pid}, {"$set": {"activo": True}})

    flash("Publicidad activada.", "success")
    return redirect(url_for("web.admin_publicidad"))


@web_bp.post("/admin/publicidad/<pub_id>/desactivar")
@login_required(role="admin")
def admin_publicidad_desactivar(pub_id):
    db = extensions.mongo_db
    pub_col = db["publicidades"]

    try:
        pid = ObjectId(pub_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.admin_publicidad"))

    pub_col.update_one({"_id": pid}, {"$set": {"activo": False}})
    flash("Publicidad desactivada.", "success")
    return redirect(url_for("web.admin_publicidad"))



# CAJERO
@web_bp.get("/cajero")
@login_required(role="cajero")
def cajero_dashboard():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    username = session.get("username")

    q = (request.args.get("q") or "").strip()
    desde = (request.args.get("desde") or "").strip()
    hasta = (request.args.get("hasta") or "").strip()

    ventas = listar_ventas_por_cajero(
        username,
        limit=20,
        q=q,
        fecha_desde=desde,
        fecha_hasta=hasta,
    )

    resumen_hoy = resumen_ventas_hoy_por_cajero(username)

    ultima_venta_list = listar_ventas_por_cajero(username, limit=1)
    ultima_venta = ultima_venta_list[0] if ultima_venta_list else None

    clientes_por_vencer = obtener_clientes_por_vencer(
        db,
        dias_objetivo=(2, 1, 0),
        limitar=200
    )

    return render_template(
        "dashboard_cajero.html",
        ventas=ventas,
        resumen_hoy=resumen_hoy,
        show_publicidad=True,
        ultima_venta=ultima_venta,
        clientes_por_vencer=clientes_por_vencer,
        q=q, desde=desde, hasta=hasta,
    )


@web_bp.get("/cajero/clientes")
@login_required(role="cajero")
def cajero_clientes():
    db = extensions.mongo_db
    ventas_col = db["ventas"]
    clientes_col = db["clientes"]
    users_col = db["users"]

    # ✅ ahora sacamos TODOS los clientes
    clientes_docs = list(clientes_col.find({}).sort("nombre", 1))

    clientes = []
    hoy = date.today()

    for cdoc in clientes_docs:
        cid = cdoc["_id"]

        u = users_col.find_one({"cliente_id": cid}, {"username": 1, "activo": 1}) or {}

        ultima = ventas_col.find_one(
            {"cliente_id": cid},
            sort=[("fecha", -1)],
            projection={"membresia": 1, "fecha": 1}
        )
        memb = ultima.get("membresia") if ultima else None
        fh = _to_date(memb.get("fecha_hasta")) if isinstance(memb, dict) else None

        clientes.append({
            "_id": cid,
            "nombre": cdoc.get("nombre", ""),
            "apellido": cdoc.get("apellido", ""),
            "telefono": cdoc.get("telefono", ""),
            "username": u.get("username", ""),
            "user_activo": bool(u.get("activo", True)),
        })

    return render_template("cajero_clientes.html", clientes=clientes)



@web_bp.get("/cajero/clientes/<cliente_id>/editar")
@login_required(role="cajero")
def cajero_cliente_editar(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    users_col = db["users"]

    oid = _oid(cliente_id)
    if not oid:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    cliente = clientes_col.find_one({"_id": oid})
    if not cliente:
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    u = users_col.find_one({"cliente_id": oid}, {"activo": 1}) or {}
    user_activo = bool(u.get("activo", True))

    return render_template(
        "cajero_cliente_form.html",
        mode="edit",
        cliente=cliente,
        user_activo=user_activo,
    )


@web_bp.post("/cajero/clientes/<cliente_id>/editar")
@login_required(role="cajero")
def cajero_cliente_editar_post(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    users_col = db["users"]

    oid = _oid(cliente_id)
    if not oid:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    nombre = (request.form.get("nombre") or "").strip()
    apellido = (request.form.get("apellido") or "").strip()
    telefono = (request.form.get("telefono") or "").strip()
    email = (request.form.get("email") or "").strip()
    identificacion = (request.form.get("identificacion") or "").strip()

    activo = (request.form.get("activo") == "on")

    if not nombre:
        flash("El nombre es obligatorio.", "danger")
        return redirect(url_for("web.cajero_cliente_editar", cliente_id=cliente_id))

    clientes_col.update_one(
        {"_id": oid},
        {"$set": {
            "nombre": nombre,
            "apellido": apellido,
            "telefono": telefono,
            "email": email,
            "identificacion": identificacion,
        }}
    )

    users_col.update_one(
        {"cliente_id": oid},
        {"$set": {"activo": activo}},
        upsert=False
    )

    flash("Cliente actualizado.", "success")
    return redirect(url_for("web.cajero_dashboard"))




@web_bp.get("/cajero/config")
@login_required(role="cajero")
def cajero_config():
    db = extensions.mongo_db
    users_col = db["users"]
    username = session.get("username")

    user = users_col.find_one({"username": username})
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.cajero_dashboard"))

    return render_template("cajero_config.html", user=user)


@web_bp.post("/cajero/config")
@login_required(role="cajero")
def cajero_config_update():
    db = extensions.mongo_db
    users_col = db["users"]
    current_username = session.get("username")

    user = users_col.find_one({"username": current_username})
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.cajero_config"))

    new_username = (request.form.get("username") or "").strip()
    email       = (request.form.get("email") or "").strip().lower()
    nombre      = (request.form.get("nombre") or "").strip()
    apellido    = (request.form.get("apellido") or "").strip()
    telefono    = (request.form.get("telefono") or "").strip()

    if not new_username or not email or not nombre or not apellido:
        flash("Completa los campos obligatorios.", "danger")
        return redirect(url_for("web.cajero_config"))

    if new_username != user.get("username"):
        exists_u = users_col.find_one({"username": new_username, "_id": {"$ne": user["_id"]}})
        if exists_u:
            flash("Ese usuario ya está en uso.", "danger")
            return redirect(url_for("web.cajero_config"))

    if email != (user.get("email") or "").lower():
        exists_e = users_col.find_one({"email": email, "_id": {"$ne": user["_id"]}})
        if exists_e:
            flash("Ese correo ya está en uso.", "danger")
            return redirect(url_for("web.cajero_config"))

    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "username": new_username,
            "email": email,
            "nombre": nombre,
            "apellido": apellido,
            "telefono": telefono
        }}
    )

    if new_username != current_username:
        session["username"] = new_username

    flash("Datos actualizados.", "success")
    return redirect(url_for("web.cajero_dashboard"))



@web_bp.get("/cajero/renovar")
@login_required(role="cajero")
def cajero_renovar():
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    ventas_col = db["ventas"]

    q = (request.args.get("q") or "").strip()

    clientes = []
    if q:
        clientes = list(clientes_col.find(
            {"$or": [
                {"nombre": {"$regex": q, "$options": "i"}},
                {"identificacion": {"$regex": q, "$options": "i"}},
                {"telefono": {"$regex": q, "$options": "i"}},
                {"email": {"$regex": q, "$options": "i"}},
            ]},
            {"nombre": 1, "identificacion": 1, "telefono": 1, "email": 1}
        ).limit(20))

    cliente_id = request.args.get("cliente_id")
    cliente = None
    ultima_venta = None
    estado = None
    dias_restantes = None

    if cliente_id:
        try:
            oid = ObjectId(cliente_id)
            cliente = clientes_col.find_one({"_id": oid}) or None
            ultima_venta = ventas_col.find_one({"cliente_id": oid}, sort=[("fecha", -1)])
        except Exception:
            cliente = None
            ultima_venta = None

    # calcula estado de membresía para mostrar
    if ultima_venta and isinstance(ultima_venta.get("membresia"), dict):
        m = ultima_venta["membresia"]
        fh = m.get("fecha_hasta")
        if isinstance(fh, datetime):
            fh = fh.date()
        hoy = date.today()
        if fh:
            if fh >= hoy:
                estado = "Activa"
                dias_restantes = (fh - hoy).days
            else:
                estado = "Vencida"
                dias_restantes = 0
    def add_months(d: date, months: int) -> date:
        y = d.year + (d.month - 1 + months) // 12
        m = (d.month - 1 + months) % 12 + 1
        last_day = calendar.monthrange(y, m)[1]
        day = min(d.day, last_day)
        return date(y, m, day)

    def to_date(x):
        if x is None:
            return None
        if isinstance(x, datetime):
            return x.date()
        if isinstance(x, date):
            return x
        return None

    today = date.today()

    inicio_default = today
    meses_default = 1

    if ultima_venta and isinstance(ultima_venta.get("membresia"), dict):
        fh = to_date(ultima_venta["membresia"].get("fecha_hasta"))
        if fh:
            if fh >= today:
                inicio_default = fh
            else:
                inicio_default = today

    fin_default = add_months(inicio_default, meses_default)
    

    return render_template(
        "cajero_renovar.html",
        q=q,
        clientes=clientes,
        cliente=cliente,
        ultima_venta=ultima_venta,
        estado=estado,
        dias_restantes=dias_restantes,
        today=today,
        inicio_default=inicio_default,
        fin_default=fin_default,
        meses_default=meses_default,
    )
    
def add_months(d: date, months: int) -> date:
    """Suma meses a una fecha (sin dependencias extrnas)."""
    y = d.year + (d.month - 1 + months) // 12
    m = (d.month - 1 + months) % 12 + 1
    last_day = calendar.monthrange(y, m)[1]
    day = min(d.day, last_day)
    return date(y, m, day)

@web_bp.post("/cajero/renovar")
@login_required(role="cajero")
def cajero_renovar_post():
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    ventas_col = db["ventas"]

    cliente_id = (request.form.get("cliente_id") or "").strip()
    meses_raw = (request.form.get("meses") or "").strip()
    concepto = (request.form.get("concepto") or "").strip()


    if not cliente_id:
        flash("Selecciona un cliente.", "danger")
        return redirect(url_for("web.cajero_renovar"))
    
    if len(concepto) > 120:
        flash("Concepto muy largo (máx 120 caracteres).", "danger")
        return redirect(url_for("web.cajero_renovar", cliente_id=cliente_id))


    try:
        oid = ObjectId(cliente_id)
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_renovar"))

    try:
        meses = int(meses_raw)
        if meses <= 0 or meses > 36:
            raise ValueError()
    except Exception:
        flash("Meses inválidos.", "danger")
        return redirect(url_for("web.cajero_renovar", cliente_id=cliente_id))

    # --- 1) Cliente ---
    cliente = clientes_col.find_one({"_id": oid})
    if not cliente:
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for("web.cajero_renovar"))

    # --- 2) Obtener última venta/membresía ---
    ultima_venta = ventas_col.find_one(
        {"cliente_id": oid},
        sort=[("fecha", -1)]
    )

    def to_date(x):
        if x is None:
            return None
        if isinstance(x, datetime):
            return x.date()
        if isinstance(x, date):
            return x
        return None

    hoy = date.today()

    # --- 3) Regla pedida: inicio = fecha_hasta anterior si está activa, sino hoy ---
    f_desde = hoy
    if ultima_venta and isinstance(ultima_venta.get("membresia"), dict):
        fh = to_date(ultima_venta["membresia"].get("fecha_hasta"))
        if fh and fh >= hoy:
            f_desde = fh  # ✅ tu regla
            # Si quisieras que empiece al día siguiente:
            # f_desde = fh + timedelta(days=1)

    f_hasta = add_months(f_desde, meses)

    doc = {
        "fecha": datetime.utcnow(),
        "vendedor": session.get("username"),
        "cliente_id": oid,
        "concepto": concepto,
        "tipo": "renovacion",
        "membresia": {
            "meses": meses,
            "fecha_desde": datetime.combine(f_desde, datetime.min.time()),
            "fecha_hasta": datetime.combine(f_hasta, datetime.min.time()),
        }
    }

    ventas_col.insert_one(doc)
    
    clientes_col.update_one(
        {"_id": oid},
        {"$set": {"activo": True}}
    )



    flash(
        f"Suscripción renovada: {f_desde.strftime('%d/%m/%Y')} → {f_hasta.strftime('%d/%m/%Y')}",
        "success"
    )
    return redirect(url_for("web.cajero_dashboard"))





@web_bp.post("/cajero/clientes/<cliente_id>/password")
@login_required(role="cajero")
def cajero_cliente_password(cliente_id):
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        flash("La confirmación no coincide.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    try:
        reset_password_cliente(cliente_id, new_password)
        flash("Contraseña del cliente actualizada. Se le pedirá cambiarla al iniciar sesión.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.cajero_clientes"))



@web_bp.get("/staff/slot-reservas")
@login_required()
def staff_slot_reservas():
    # ✅ solo admin/cajero
    if session.get("user_role") not in ("admin", "cajero"):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    reservas_col = db["reservas"]

    slot_id = (request.args.get("slot_id") or "").strip()
    if not slot_id:
        return jsonify({"ok": False, "error": "slot_id inválido"}), 400

    pipeline = [
        {"$match": {"slot_id": slot_id, "estado": {"$ne": "cancelada"}, "cancelada": {"$ne": True}}},
        {"$lookup": {"from": "clientes", "localField": "cliente_id", "foreignField": "_id", "as": "cliente"}},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "users", "localField": "entrenador_id", "foreignField": "_id", "as": "entrenador"}},
        {"$unwind": {"path": "$entrenador", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "_id": 0,
            "reserva_id": {"$toString": "$_id"},
            "cliente_nombre": {
                "$trim": {"input": {"$concat": [
                    {"$ifNull": ["$cliente.nombre", ""]},
                    " ",
                    {"$ifNull": ["$cliente.apellido", ""]}
                ]}}
            },
            "cliente_identificacion": {"$ifNull": ["$cliente.identificacion", ""]},
            "entrenador_nombre": {"$ifNull": ["$entrenador.username", "-"]},
            "estado": {"$ifNull": ["$estado", "confirmada"]},
        }},
        {"$sort": {"cliente_nombre": 1}},
    ]

    rows = list(reservas_col.aggregate(pipeline))

    reservas = [{
        "reserva_id": r.get("reserva_id"),
        "cliente": (r.get("cliente_nombre") or "-").strip() or "-",
        "identificacion": (r.get("cliente_identificacion") or "").strip(),
        "entrenador": (r.get("entrenador_nombre") or "-").strip(),
        "estado": (r.get("estado") or "").strip(),
    } for r in rows]

    return jsonify({"ok": True, "slot_id": slot_id, "reservas": reservas})




@web_bp.post("/staff/reservas/<reserva_id>/cancelar")
@login_required()
def staff_cancelar_reserva(reserva_id):
    if session.get("user_role") not in ("admin", "cajero"):
        return jsonify({"ok": False, "error": "No autorizado"}), 403

    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")
    reservas_col = db["reservas"]

    try:
        rid = ObjectId(reserva_id)
    except Exception:
        return jsonify({"ok": False, "error": "ID de reserva inválido"}), 400

    r = reservas_col.find_one({"_id": rid})
    if not r:
        return jsonify({"ok": False, "error": "Reserva no existe"}), 404

    if r.get("estado") == "cancelada" or r.get("cancelada") is True:
        return jsonify({"ok": True, "estado": "cancelada"})

    reservas_col.update_one(
        {"_id": rid},
        {"$set": {
            "estado": "cancelada",
            "cancelada": True,
            "cancelada_at": datetime.now(timezone.utc),
            "cancelada_por": session.get("username"),
            "cancelada_por_rol": session.get("user_role"),
        }}
    )
    return jsonify({"ok": True, "estado": "cancelada"})


# ENTRENADOR

@web_bp.get("/entrenador")
@login_required(role="entrenador")
def entrenador_dashboard():
    users = get_users_collection()
    entrenador = users.find_one({"username": session.get("username"), "role": "entrenador"})
    if not entrenador:
        flash("Entrenador no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    # ✅ SOLO hoy + ORDENADO (más reciente primero)
    ahora_local, clases_hoy, tz = obtener_clases_hoy_entrenador(entrenador["_id"])

    return render_template(
        "dashboard_entrenador.html",
        entrenador=entrenador,
        show_publicidad=True,
        ahora_local=ahora_local,
        clases_hoy=clases_hoy,
        tz=tz,
        activate="entrenador_dashboard",
    )


@web_bp.get("/entrenador/slot-alumnos")
@login_required(role="entrenador")
def entrenador_slot_alumnos():
    db = extensions.mongo_db
    reservas_col = db["reservas"]
    clientes_col = db["clientes"]  # (no es necesario aquí, pero lo dejo)
    plan_col = db["planificaciones"]  # ✅ NUEVO

    slot_id = (request.args.get("slot_id") or "").strip()
    if not slot_id or "|" not in slot_id:
        return jsonify({"ok": False, "error": "slot_id inválido"}), 400

    try:
        entrenador_oid = ObjectId(session["user_id"])
    except Exception:
        return jsonify({"ok": False, "error": "Entrenador inválido"}), 400

    pipeline = [
        {"$match": {
            "entrenador_id": entrenador_oid,
            "estado": {"$ne": "cancelada"},
            "slot_id": slot_id,
        }},
        {"$lookup": {
            "from": "clientes",
            "localField": "cliente_id",
            "foreignField": "_id",
            "as": "cliente",
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},
        {"$project": {
            "_id": 0,
            "cliente_id": 1,
            "nombre": {"$ifNull": ["$cliente.nombre", ""]},
            "apellido": {"$ifNull": ["$cliente.apellido", ""]},
        }},
        {"$sort": {"apellido": 1, "nombre": 1}},
    ]

    rows = list(reservas_col.aggregate(pipeline))

    alumnos = []
    for r in rows:
        cliente_id = r.get("cliente_id")
        cliente_id_str = str(cliente_id) if cliente_id else ""

        nombre_completo = (f"{(r.get('nombre') or '').strip()} {(r.get('apellido') or '').strip()}").strip() or "-"

        # ✅ buscar ÚLTIMA planificación (de este entrenador para este alumno)
        plan = None
        if cliente_id:
            plan = plan_col.find_one(
                {"entrenador_id": entrenador_oid, "cliente_id": cliente_id},
                sort=[("creado", -1)],
                projection={"filename": 1, "bytes": 1}
            )

        plan_id = str(plan["_id"]) if plan else None
        plan_filename = plan.get("filename") if plan else None
        plan_bytes = int(plan.get("bytes", 0)) if plan else None

        alumnos.append({
            "cliente_id": cliente_id_str,
            "nombre": nombre_completo,

            # ✅ NUEVO
            "plan_id": plan_id,
            "plan_filename": plan_filename,
            "plan_bytes": plan_bytes,
            "plan_download_url": url_for("web.descargar_planificacion", plan_id=plan_id) if plan_id else None,
        })

    return jsonify({"ok": True, "slot_id": slot_id, "alumnos": alumnos})


@web_bp.get("/entrenador/configuracion")
@login_required(role="entrenador")
def entrenador_configuracion():
    ent = obtener_entrenador_por_username(session.get("username"))
    if not ent:
        flash("Entrenador no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    return render_template(
        "entrenador_config.html",
        entrenador=ent,
        active="entrenador_configuracion",
    )


@web_bp.post("/entrenador/configuracion/perfil")
@login_required(role="entrenador")
def entrenador_configuracion_perfil():
    ent = obtener_entrenador_por_username(session.get("username"))
    if not ent:
        flash("Entrenador no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    username = request.form.get("username", "").strip()
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip()
    telefono = request.form.get("telefono", "").strip()

    try:
        actualizado = actualizar_perfil_entrenador(
            ent["_id"],
            username=username,
            nombre=nombre,
            email=email,
            telefono=telefono,
        )
        # Si cambió username => actualiza sesión
        session["username"] = actualizado["username"]
        flash("Perfil actualizado correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.entrenador_configuracion"))


@web_bp.post("/entrenador/configuracion/password")
@login_required(role="entrenador")
def entrenador_configuracion_password():
    ent = obtener_entrenador_por_username(session.get("username"))
    if not ent:
        flash("Entrenador no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    password_actual = request.form.get("current_password", "")
    password_nuevo = request.form.get("new_password", "")
    password_confirmar = request.form.get("confirm_password", "")

    if password_nuevo != password_confirmar:
        flash("La confirmación no coincide.", "danger")
        return redirect(url_for("web.entrenador_configuracion"))

    try:
        cambiar_password_entrenador(ent["_id"], password_actual, password_nuevo)
        flash("Contraseña actualizada correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("web.entrenador_configuracion"))



@web_bp.get("/entrenador/alumnos")
@login_required(role="entrenador")
def entrenador_mis_alumnos():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    reservas_col = db["reservas"]
    plan_col = db["planificaciones"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
    except Exception:
        flash("Entrenador inválido.", "danger")
        return redirect(url_for("web.logout"))

    # ✅ Alumnos = clientes que tienen al menos 1 reserva con este entrenador
    pipeline = [
        {"$match": {"entrenador_id": entrenador_oid, "estado": {"$ne": "cancelada"}}},
        {"$group": {"_id": "$cliente_id", "total_reservas": {"$sum": 1}}},
        {"$lookup": {
            "from": "clientes",
            "localField": "_id",
            "foreignField": "_id",
            "as": "cliente"
        }},
        {"$unwind": {"path": "$cliente", "preserveNullAndEmptyArrays": True}},

        # ✅ Traer planificación (como es 1 por alumno, trae 0 o 1)
        {"$lookup": {
            "from": "planificaciones",
            "let": {"cid": "$_id"},
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$eq": ["$cliente_id", "$$cid"]},
                    {"$eq": ["$entrenador_id", entrenador_oid]},
                ]}}},
                {"$project": {"filename": 1, "bytes": 1, "updated_at": 1, "creado": 1}},
            ],
            "as": "plan"
        }},
        {"$addFields": {"plan": {"$arrayElemAt": ["$plan", 0]}}},
        {"$project": {
            "_id": 1,
            "total_reservas": 1,
            "nombre": {"$ifNull": ["$cliente.nombre", ""]},
            "apellido": {"$ifNull": ["$cliente.apellido", ""]},
            "telefono": {"$ifNull": ["$cliente.telefono", ""]},
            "plan_id": {"$toString": "$plan._id"},
            "plan_filename": "$plan.filename",
            "plan_bytes": "$plan.bytes",
            "plan_updated_at": {"$ifNull": ["$plan.updated_at", "$plan.creado"]},
        }},
        {"$sort": {"apellido": 1, "nombre": 1}},
    ]

    alumnos = list(reservas_col.aggregate(pipeline))

    # Normaliza plan_id (si no existe, queda None)
    for a in alumnos:
        if not a.get("plan_filename"):
            a["plan_id"] = None

    return render_template(
        "alumnos.html",
        alumnos=alumnos,
        active="entrenador_mis_alumnos",
    )

@web_bp.get("/entrenador/alumnos/<cliente_id>")
@login_required(role="entrenador")
def entrenador_alumno_detalle(cliente_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    clientes_col = db["clientes"]
    plan_col = db["planificaciones"]
    fotos_col = db["progreso_fotos"]


    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    # ✅ seguridad: debe ser su alumno (tiene reservas con él)
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        flash("Ese alumno no pertenece a tu agenda.", "warning")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    alumno = clientes_col.find_one({"_id": cliente_oid}, {"nombre": 1, "apellido": 1, "telefono": 1, "email": 1})
    if not alumno:
        flash("Alumno no encontrado.", "danger")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    plan = plan_col.find_one(
        {"entrenador_id": entrenador_oid, "cliente_id": cliente_oid},
        projection={"filename": 1, "bytes": 1, "images": 1, "updated_at": 1, "creado": 1}
    )
    
    medidas_col = db["progreso_medidas"]

    medidas = list(
        medidas_col.find(
            {"cliente_id": cliente_oid, "entrenador_id": entrenador_oid},
            projection={"fecha": 1, "peso_kg": 1, "grasa_pct": 1, "musculo_pct": 1}
        ).sort("fecha", 1).limit(60)
    )

    latest, prev, chart_json = _build_kpi_and_chart(medidas)
    
    fotos_progreso = list(
        fotos_col.find(
            {"cliente_id": cliente_oid},
            projection={"filename": 1, "bytes": 1, "creado": 1, "rel_path": 1}
        ).sort("creado", -1).limit(60)
    )


    return render_template(
        "alumno_detalle.html",
        alumno=alumno,
        cliente_id=str(cliente_oid),
        plan=plan,
        medidas=medidas,
        kpi_latest=latest,
        fotos_progreso=fotos_progreso,
        kpi_prev=prev,
        chart_json=chart_json,
        active="entrenador_mis_alumnos",
    )

@web_bp.post("/entrenador/alumno/<cliente_id>/medidas")
@login_required(role="entrenador")
def entrenador_medidas_crear(cliente_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    medidas_col = db["progreso_medidas"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    # seguridad: alumno pertenece al entrenador
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        flash("Ese alumno no pertenece a tu agenda.", "warning")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    # valores
    fecha_raw = (request.form.get("fecha") or "").strip()
    peso_raw = request.form.get("peso_kg")
    grasa_raw = request.form.get("grasa_pct")
    musculo_raw = request.form.get("musculo_pct")

    # fecha (opcional) -> si no viene, hoy UTC
    if fecha_raw:
        try:
            # input type="date" => YYYY-MM-DD
            fecha_dt = datetime.strptime(fecha_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            flash("Fecha inválida.", "danger")
            return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))
    else:
        fecha_dt = datetime.now(timezone.utc)

    peso = _as_float_form(peso_raw, 20, 400)
    grasa = _as_float_form(grasa_raw, 1, 80)
    musculo = _as_float_form(musculo_raw, 1, 80)

    if peso is None or grasa is None or musculo is None:
        flash("Valores inválidos. Revisa peso, %grasa y %músculo.", "danger")
        return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    medidas_col.insert_one({
        "cliente_id": cliente_oid,
        "entrenador_id": entrenador_oid,
        "fecha": fecha_dt,
        "peso_kg": float(peso),
        "grasa_pct": float(grasa),
        "musculo_pct": float(musculo),
    })

    flash("Medición guardada.", "success")
    return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))


@web_bp.get("/entrenador/alumno/<cliente_id>/progreso/foto/<foto_id>")
@login_required(role="entrenador")
def entrenador_progreso_ver_foto(cliente_id, foto_id):
    db = extensions.mongo_db
    fotos_col = db["progreso_fotos"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
        fid = ObjectId(foto_id)
    except Exception:
        abort(400)

    # ✅ seguridad: solo si el alumno pertenece al entrenador
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        abort(403)

    doc = fotos_col.find_one({"_id": fid})
    if not doc:
        abort(404)

    # ✅ la foto debe ser de ese cliente
    if doc.get("cliente_id") != cliente_oid:
        abort(403)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    return send_file(abs_path, as_attachment=False)


@web_bp.get("/entrenador/alumno/<cliente_id>/progreso/foto/<foto_id>/download")
@login_required(role="entrenador")
def entrenador_progreso_descargar_foto(cliente_id, foto_id):
    db = extensions.mongo_db
    fotos_col = db["progreso_fotos"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
        fid = ObjectId(foto_id)
    except Exception:
        abort(400)

    # ✅ seguridad: solo si el alumno pertenece al entrenador
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        abort(403)

    doc = fotos_col.find_one({"_id": fid})
    if not doc:
        abort(404)

    # ✅ la foto debe ser de ese cliente
    if doc.get("cliente_id") != cliente_oid:
        abort(403)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    filename = doc.get("filename") or "foto.jpg"
    return send_file(abs_path, as_attachment=True, download_name=filename)


@web_bp.post("/entrenador/alumno/<cliente_id>/progreso/foto/<foto_id>/eliminar")
@login_required(role="entrenador")
def entrenador_progreso_eliminar_foto(cliente_id, foto_id):
    db = extensions.mongo_db
    fotos_col = db["progreso_fotos"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
        fid = ObjectId(foto_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    # ✅ seguridad: solo si el alumno pertenece al entrenador
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        flash("Ese alumno no pertenece a tu agenda.", "warning")
        return redirect(url_for("web.entrenador_mis_alumnos"))

    doc = fotos_col.find_one({"_id": fid})
    if not doc:
        flash("Foto no encontrada.", "warning")
        return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    # ✅ la foto debe ser de ese cliente
    if doc.get("cliente_id") != cliente_oid:
        flash("No autorizado.", "danger")
        return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    # borrar archivo físico
    rel_path = doc.get("rel_path")
    if rel_path:
        abs_path = os.path.join(os.getcwd(), rel_path)
        if os.path.exists(abs_path):
            try:
                # usa tu helper si existe
                safe_delete_or_quarantine(abs_path)
            except Exception:
                try:
                    os.remove(abs_path)
                except Exception:
                    pass

    # borrar doc de Mongo
    fotos_col.delete_one({"_id": fid})

    flash("Foto eliminada.", "success")
    return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

# Cliente

def _to_date(value):
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        s = value.strip()
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except Exception:
                pass
    return None


@web_bp.get("/cliente/force-password")
@login_required(role="cliente")
def cliente_force_password():
    # si por alguna razón no está forzado, lo mandas al dashboard cliente
    if not session.get("force_pw_change"):
        return redirect(url_for("web.cliente_dashboard"))  # ajusta a tu endpoint real
    return render_template("cliente_force_password.html")


@web_bp.post("/cliente/force-password")
@login_required(role="cliente")
def cliente_force_password_post():
    db = extensions.mongo_db
    users_col = db["users"]

    new1 = request.form.get("new_password", "")
    new2 = request.form.get("new_password2", "")

    if not new1 or new1 != new2:
        flash("La nueva contraseña no coincide.", "danger")
        return redirect(url_for("web.cliente_force_password"))

    username = session.get("username")
    user = users_col.find_one({"username": username, "role": "cliente", "activo": True})
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password": bcrypt.generate_password_hash(new1).decode("utf-8"),  
            "must_change_password": False,                                  
        }}
    )

    session.pop("force_pw_change", None)
    flash("Contraseña actualizada.", "success")
    return redirect(url_for("web.cliente_dashboard"))  


@web_bp.get("/cliente")
@login_required(role="cliente")
def cliente_dashboard():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    clientes_col = db["clientes"]
    ventas_col = db["ventas"]
    reservas_col = db["reservas"]
    noti_col = db["notificaciones"]
    users_col = db["users"]  # ✅ NUEVO (para mostrar entrenador)
    plan_col = db["planificaciones"]

    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("web.logout"))

    cliente_id = ObjectId(user_id)
    
    plan_actual = plan_col.find_one(
        {"cliente_id": cliente_id},
        sort=[("updated_at", -1), ("creado", -1)],
        projection={"filename": 1, "bytes": 1, "updated_at": 1, "creado": 1, "rel_path": 1}
    )


    # --- cliente perfil ---
    cliente = clientes_col.find_one({"_id": cliente_id})

    # --- última venta => membresía actual ---
    venta = ventas_col.find_one({"cliente_id": cliente_id}, sort=[("fecha", -1)])
    membresia = (venta or {}).get("membresia") if venta else None

    from zoneinfo import ZoneInfo
    TZ_EC = ZoneInfo("America/Guayaquil")

    estado_membresia = "Sin membresía"
    dias_restantes = None
    alertas_membresia = []  # ✅ SIEMPRE inicializado

    ahora_utc = datetime.now(timezone.utc)
    hoy_ec = ahora_utc.astimezone(TZ_EC).date()

    fh = None
    fh_ec_date = None

    if membresia and membresia.get("fecha_hasta"):
        fh = membresia.get("fecha_hasta")

        # ✅ normalizar fh (Mongo a veces devuelve naive)
        if isinstance(fh, datetime) and fh.tzinfo is None:
            fh = fh.replace(tzinfo=timezone.utc)

        fh_ec_date = fh.astimezone(TZ_EC).date()

        # ✅ cálculo POR FECHA (no por horas)
        dias_restantes = (fh_ec_date - hoy_ec).days

        if dias_restantes >= 0:
            estado_membresia = "Activa"
        else:
            estado_membresia = "Vencida"
            dias_restantes = None  # ✅ no mostrar días si ya venció

            # ✅ Cerrar notificaciones activas de membresía para que NO sigan saliendo
            noti_col.update_many(
                {
                    "cliente_id": cliente_id,
                    "estado": "activa",
                    "tipo": {"$in": ["membresia_5_dias", "membresia_3_dias"]},
                },
                {"$set": {"estado": "cerrada", "cerrada": ahora_utc}}
            )

            # ✅ Mostrar una alerta útil (renovar)
            alertas_membresia = ["Tu membresía está vencida. Renueva para mantener el acceso."]

    def _push_noti(tipo: str, mensaje: str, fh_dt: datetime):
        existe = noti_col.find_one({
            "cliente_id": cliente_id,
            "tipo": tipo,
            "fecha_hasta": fh_dt,
            "estado": "activa",
        })
        if not existe:
            noti_col.insert_one({
                "cliente_id": cliente_id,
                "tipo": tipo,
                "mensaje": mensaje,
                "fecha_hasta": fh_dt,
                "estado": "activa",
                "creado": ahora_utc,
            })
        alertas_membresia.append(mensaje)

    # ✅ ALERTA "dinámica" (SIEMPRE que falten pocos días)
    if estado_membresia == "Activa" and dias_restantes is not None and fh is not None:
        # 1) Mensaje visible aunque NO haya notificación guardada
        if 0 <= dias_restantes <= 5:
            if dias_restantes == 0:
                alertas_membresia.append("⚠️ Tu membresía vence HOY. Renueva para no perder el acceso.")
            elif dias_restantes == 1:
                alertas_membresia.append("⚠️ Tu membresía vence MAÑANA. Renueva para no perder el acceso.")
            elif dias_restantes <= 3:
                alertas_membresia.append(f"⚠️ Tu membresía vence en {dias_restantes} días. Si no renuevas, se desactivará.")
            else:
                alertas_membresia.append(f"Tu membresía vence en {dias_restantes} días. Recuerda renovarla para no perder el acceso.")

        # 2) Notificación "persistente" (solo se guarda 1 vez en BD)
        if dias_restantes == 5:
            _push_noti(
                "membresia_5_dias",
                "Tu membresía vence en 5 días. Recuerda renovarla para no perder el acceso.",
                fh
            )
        elif dias_restantes == 3:
            _push_noti(
                "membresia_3_dias",
                "⚠️ Tu membresía vence en 3 días. Si no renuevas, se desactivará automáticamente.",
                fh
            )

    # ✅ Si no hay alerta dinámica, recién ahí carga notis activas guardadas
    if estado_membresia == "Activa" and not alertas_membresia:
        docs_noti = list(
            noti_col.find(
                {
                    "cliente_id": cliente_id,
                    "estado": "activa",
                    "tipo": {"$in": ["membresia_5_dias", "membresia_3_dias"]},
                },
                {"mensaje": 1}
            ).sort("creado", -1).limit(3)
        )
        alertas_membresia = [n.get("mensaje") for n in docs_noti if n.get("mensaje")]


    # --- reservas del cliente ---
    reservas = list(
        reservas_col.find(
            {"cliente_id": cliente_id, "estado": "confirmada"},
            {
                "slot_id": 1,
                "entrenador_id": 1,  # ✅ NUEVO
                "entrenador": 1,     # ✅ compatibilidad (si tienes reservas viejas)
                "entrenador_username": 1,  # ✅ si lo guardaste opcionalmente
                "creado": 1
            }
        ).sort("slot_id", 1).limit(30)
    )

    # ✅ Mapa entrenador_id => username (para pintar el nombre)
    entrenador_ids = []
    for r in reservas:
        eid = r.get("entrenador_id")
        if isinstance(eid, ObjectId):
            entrenador_ids.append(eid)
        elif isinstance(eid, str):
            try:
                entrenador_ids.append(ObjectId(eid))
            except Exception:
                pass

    entrenador_map = {}
    if entrenador_ids:
        for u in users_col.find({"_id": {"$in": list(set(entrenador_ids))}}, {"username": 1}):
            entrenador_map[str(u["_id"])] = u.get("username") or "-"

    clases = []
    ahora = ahora_utc

    for r in reservas:
        slot_id = (r.get("slot_id") or "")
        if "|" not in slot_id:
            continue

        fecha_txt, hhmm = slot_id.split("|", 1)

        dt_slot = None
        try:
            dt_slot = datetime.strptime(f"{fecha_txt} {hhmm}", "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            dt_slot = None

        # ✅ entrenador visible
        entrenador_nombre = "-"
        if r.get("entrenador_username"):
            entrenador_nombre = r.get("entrenador_username")
        else:
            eid = r.get("entrenador_id")
            if isinstance(eid, ObjectId):
                entrenador_nombre = entrenador_map.get(str(eid), "-")
            elif isinstance(eid, str):
                entrenador_nombre = entrenador_map.get(eid, "-")
            else:
                # compatibilidad con reservas viejas que guardaban "entrenador": "username"
                entrenador_nombre = r.get("entrenador") or "-"

        clases.append({
            "_id": str(r["_id"]),
            "slot_id": slot_id,
            "fecha_txt": fecha_txt,
            "hora": hhmm,
            "dt": dt_slot,
            "entrenador": entrenador_nombre,  # ✅ ya listo para el template
            "es_proxima": (dt_slot is not None and dt_slot >= ahora),
        })

    clases_prox = sorted([c for c in clases if c["es_proxima"]], key=lambda x: x["dt"] or ahora)
    clases_pas = sorted([c for c in clases if not c["es_proxima"]], key=lambda x: x["dt"] or ahora, reverse=True)
    
    manana = datetime.now(TZ_EC).date() + timedelta(days=1)
    manana_key = manana.isoformat()

    # busca reserva confirmada de mañana del cliente
    reserva_manana = reservas_col.find_one(
        {
            "cliente_id": cliente_id,
            "estado": "confirmada",
            # si tu fecha es string "YYYY-MM-DD"
            "fecha": manana_key,
            # si tu fecha fuera ISODate, dímelo y te lo ajusto
        },
        {"_id": 1, "slot_id": 1, "fecha": 1, "entrenador_id": 1, "no_asistire": 1}
    )

    # bandera para mostrar botón
    puede_no_asistir = bool(reserva_manana) and not bool((reserva_manana or {}).get("no_asistire"))
    

    return render_template(
        "dashboard_cliente.html",
        cliente=cliente,
        membresia=membresia,
        show_publicidad=True,
        estado_membresia=estado_membresia,
        dias_restantes=dias_restantes,
        alertas_membresia=alertas_membresia,
        clases_proximas=clases_prox,
        reserva_manana=reserva_manana,
        puede_no_asistir=puede_no_asistir,
        manana_key=manana_key,

        clases_pasadas=clases_pas,
        plan_actual=plan_actual,
    )

@web_bp.post("/cliente/no_podre_asistir_manana")
@login_required(role="cliente")
def cliente_no_podre_asistir_manana():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    reservas_col = db["reservas"]
    noti_col = db["notificaciones"]
    clientes_col = db["clientes"]

    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("web.logout"))

    cliente_id = ObjectId(user_id)

    from zoneinfo import ZoneInfo
    from datetime import datetime, timedelta
    TZ_EC = ZoneInfo("America/Guayaquil")

    manana = datetime.now(TZ_EC).date() + timedelta(days=1)
    manana_key = manana.isoformat()

    # 1) busco la reserva de mañana
    reserva = reservas_col.find_one(
        {"cliente_id": cliente_id, "estado": "confirmada", "fecha": manana_key},
        {"_id": 1, "no_asistire": 1, "slot_id": 1, "fecha": 1, "entrenador_id": 1}
    )

    if not reserva:
        flash("No tienes una reserva confirmada para mañana.", "warning")
        return redirect(url_for("web.cliente_dashboard"))

    if reserva.get("no_asistire") is True:
        flash("Ya marcaste que no podrás asistir mañana.", "info")
        return redirect(url_for("web.cliente_dashboard"))

    # 2) marco la reserva
    now_ec = datetime.now(TZ_EC)
    reservas_col.update_one(
        {"_id": reserva["_id"]},
        {"$set": {
            "no_asistire": True,
            "no_asistire_at": now_ec
        }}
    )

    # 3) creo notificación para admin
    cli = clientes_col.find_one({"_id": cliente_id}, {"nombre": 1, "apellido": 1, "identificacion": 1})
    nombre = ((cli or {}).get("nombre") or "")
    apellido = ((cli or {}).get("apellido") or "")
    ident = ((cli or {}).get("identificacion") or "")
    nombre_full = f"{nombre} {apellido}".strip() or (session.get("username") or "Cliente")

    noti_col.insert_one({
        "tipo": "no_asistire",
        "rol_destino": "admin",                # para que admin lo vea
        "cliente_id": cliente_id,
        "reserva_id": reserva["_id"],
        "fecha": manana_key,
        "mensaje": f"{nombre_full} ({ident}) no podrá asistir mañana a su clase.",
        "leido": False,
        "created_at": now_ec,
    })

    flash("Listo. Se notificó al administrador que no podrás asistir mañana.", "success")
    return redirect(url_for("web.cliente_dashboard"))

@web_bp.get("/cliente/config")
@login_required(role="cliente")
def cliente_config():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    clientes_col = db["clientes"]
    users_col = db["users"]

    cliente_id = ObjectId(session["user_id"])

    # Perfil cliente
    cliente = clientes_col.find_one({"_id": cliente_id})
    if not cliente:
        flash("No se encontró tu perfil.", "danger")
        return redirect(url_for("web.cliente_dashboard"))
    
    fn = cliente.get("fecha_nacimiento")
    fecha_nacimiento_val = ""
    if isinstance(fn, datetime):
        # si viene naive desde mongo, lo tratamos como UTC
        if fn.tzinfo is None:
            fn = fn.replace(tzinfo=timezone.utc)
        fecha_nacimiento_val = fn.date().isoformat()  # "YYYY-MM-DD"
    elif isinstance(fn, str):
        # por si algún dato viejo quedó como string
        fecha_nacimiento_val = fn.strip()

    # Username desde users por cliente_id
    user = users_col.find_one({"cliente_id": cliente_id}, {"username": 1})
    username = (user or {}).get("username", "")

    return render_template(
        "cliente_config.html",
        cliente=cliente,
        username=username,
        fecha_nacimiento_val=fecha_nacimiento_val,
    )


@web_bp.post("/cliente/config")
@login_required(role="cliente")
def cliente_config_post():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    clientes_col = db["clientes"]
    users_col = db["users"]

    cliente_id = ObjectId(session["user_id"])

    # Confirmar que existe
    cliente = clientes_col.find_one({"_id": cliente_id})
    if not cliente:
        flash("No se encontró tu perfil.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    # ---- leer campos permitidos ----
    identificacion = (request.form.get("identificacion") or "").strip()
    nombre = (request.form.get("nombre") or "").strip()
    apellido = (request.form.get("apellido") or "").strip()
    email = (request.form.get("email") or "").strip()
    telefono = (request.form.get("telefono") or "").strip()
    fecha_nacimiento_raw = (request.form.get("fecha_nacimiento") or "").strip()  # "YYYY-MM-DD" o ""
    fecha_nacimiento_dt = None
    if fecha_nacimiento_raw:
        try:
            # guardamos como ISODate (datetime) en UTC
            fecha_nacimiento_dt = datetime.strptime(fecha_nacimiento_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            flash("Fecha de nacimiento inválida.", "danger")
            return redirect(url_for("web.cliente_config"))


    # ---- validaciones mínimas ----
    if not identificacion:
        flash("La identificación es obligatoria.", "danger")
        return redirect(url_for("web.cliente_config"))

    if not nombre:
        flash("El nombre es obligatorio.", "danger")
        return redirect(url_for("web.cliente_config"))

    # Email opcional, pero si viene, validar formato
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        flash("Email inválido.", "danger")
        return redirect(url_for("web.cliente_config"))

    # Evitar duplicar identificación con otro cliente
    existe_otro = clientes_col.find_one(
        {"identificacion": identificacion, "_id": {"$ne": cliente_id}},
        {"_id": 1}
    )
    if existe_otro:
        flash("Ya existe otro cliente con esa identificación.", "danger")
        return redirect(url_for("web.cliente_config"))

    # ---- update cliente ----
    update_cliente = {
        "identificacion": identificacion,
        "nombre": nombre,
        "apellido": apellido or None,
        "email": email or None,
        "telefono": telefono or None,
        "fecha_nacimiento": fecha_nacimiento_dt, 
    }

    clientes_col.update_one({"_id": cliente_id}, {"$set": update_cliente})


    users_col.update_one(
        {"cliente_id": cliente_id},
        {"$set": {"cliente_id": cliente_id}},
        upsert=False
    )

    flash("Datos actualizados correctamente.", "success")
    return redirect(url_for("web.cliente_dashboard"))


@web_bp.get("/cliente/progreso")
@login_required(role="cliente")
def cliente_progreso():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    plan_col = db["planificaciones"]
    fotos_col = db["progreso_fotos"]

    try:
        cliente_oid = ObjectId(session["user_id"])
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.logout"))

    plan_actual = plan_col.find_one(
        {"cliente_id": cliente_oid},
        sort=[("updated_at", -1), ("creado", -1)],
        projection={"filename": 1, "rel_path": 1, "bytes": 1, "images": 1, "updated_at": 1, "creado": 1}
    )

    fotos = list(fotos_col.find(
        {"cliente_id": cliente_oid},
        projection={"filename": 1, "bytes": 1, "creado": 1}
    ).sort("creado", -1).limit(60))
    
    medidas_col = db["progreso_medidas"]

    medidas = list(
        medidas_col.find(
            {"cliente_id": cliente_oid},
            projection={"fecha": 1, "peso_kg": 1, "grasa_pct": 1, "musculo_pct": 1}
        ).sort("fecha", 1).limit(90)
    )

    latest, prev, chart_json = _build_kpi_and_chart(medidas)

    return render_template(
        "cliente_progreso.html",
        plan_actual=plan_actual,
        fotos=fotos,
        medidas=medidas,
        kpi_latest=latest,
        kpi_prev=prev,
        chart_json=chart_json,
        active="cliente_progreso"
    )


@web_bp.post("/cliente/progreso/foto/subir")
@login_required(role="cliente")
def cliente_progreso_subir_foto():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    fotos_col = db["progreso_fotos"]

    try:
        cliente_oid = ObjectId(session["user_id"])
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.logout"))

    files = request.files.getlist("foto")
    files = [x for x in (files or []) if x and x.filename]

    if not files:
        flash("No se subió ninguna imagen.", "warning")
        return redirect(url_for("web.cliente_progreso"))

    # ✅ LIMITE TOTAL (acumulado)
    MAX_FOTOS_TOTAL = 4
    existentes = fotos_col.count_documents({"cliente_id": cliente_oid})

    if existentes >= MAX_FOTOS_TOTAL:
        flash("Ya tienes 4 fotos registradas. Elimina una para poder subir otra.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    if existentes + len(files) > MAX_FOTOS_TOTAL:
        restantes = MAX_FOTOS_TOTAL - existentes
        flash(f"Solo puedes subir {restantes} foto(s) más. Límite total: 4.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    # ✅ validar formatos
    for f in files:
        if not allowed_image(f.filename):
            flash("Formato no permitido. Usa JPG, PNG o WEBP.", "danger")
            return redirect(url_for("web.cliente_progreso"))

    base_dir = os.path.join(os.getcwd(), "uploads", "progreso", str(cliente_oid))
    os.makedirs(base_dir, exist_ok=True)
    tmp_dir = os.path.join(base_dir, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    subidas_ok = 0

    for f in files:
        original_name = secure_filename(f.filename)
        ts_tmp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{original_name}")

        f.save(tmp_path)
        try:
            f.close()
        except Exception:
            pass

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        final_name = f"foto_{ts}.jpg"
        final_path = os.path.join(base_dir, final_name)
        final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}.jpg")

        try:
            optimizar_imagen(tmp_path, final_tmp_path, max_side=1600, quality=82)
            replace_with_retry(final_tmp_path, final_path)
        except Exception:
            try:
                optimizar_imagen(tmp_path, final_tmp_path, max_side=2000, quality=85)
                replace_with_retry(final_tmp_path, final_path)
            except Exception:
                replace_with_retry(tmp_path, final_path)
        finally:
            safe_delete_or_quarantine(tmp_path)
            safe_delete_or_quarantine(final_tmp_path)

        if not os.path.exists(final_path):
            continue

        file_size = os.path.getsize(final_path)
        rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

        fotos_col.insert_one({
            "cliente_id": cliente_oid,
            "filename": final_name,
            "rel_path": rel_path,
            "bytes": int(file_size),
            "creado": datetime.now(timezone.utc),
        })

        subidas_ok += 1

    if subidas_ok == 0:
        flash("No se pudo guardar ninguna imagen. Intenta nuevamente.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    flash(f"Subidas {subidas_ok} foto(s). Total actual: {existentes + subidas_ok} / {MAX_FOTOS_TOTAL}.", "success")
    return redirect(url_for("web.cliente_progreso"))


@web_bp.get("/cliente/progreso/foto/<foto_id>")
@login_required(role="cliente")
def cliente_progreso_ver_foto(foto_id):
    db = extensions.mongo_db
    fotos_col = db["progreso_fotos"]

    try:
        fid = ObjectId(foto_id)
        cliente_oid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = fotos_col.find_one({"_id": fid})
    if not doc:
        abort(404)

    if doc.get("cliente_id") != cliente_oid:
        abort(403)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    return send_file(abs_path, as_attachment=False)


@web_bp.post("/cliente/progreso/foto/<foto_id>/eliminar")
@login_required(role="cliente")
def cliente_progreso_eliminar_foto(foto_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    fotos_col = db["progreso_fotos"]

    try:
        fid = ObjectId(foto_id)
        cliente_oid = ObjectId(session["user_id"])
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    doc = fotos_col.find_one({"_id": fid})
    if not doc:
        flash("Foto no encontrada.", "warning")
        return redirect(url_for("web.cliente_progreso"))

    if doc.get("cliente_id") != cliente_oid:
        flash("No tienes permisos para eliminar esta foto.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    rel_path = doc.get("rel_path")
    if rel_path:
        abs_path = os.path.join(os.getcwd(), rel_path)
        if os.path.exists(abs_path):
            safe_delete_or_quarantine(abs_path)

    # borrar doc en mongo
    fotos_col.delete_one({"_id": fid})

    flash("Foto eliminada.", "success")
    return redirect(url_for("web.cliente_progreso"))



# Horarios Semanales
@web_bp.get("/horarios")
@login_required()
def horarios_publico():
    primera_vez = False
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    semanas_col = db["horarios_dias"]
    users_col = db["users"]
    reservas_col = db["reservas"]

    view = request.args.get("view", "week")
    fecha_raw = request.args.get("fecha")

    try:
        d = datetime.strptime(fecha_raw, "%Y-%m-%d").date() if fecha_raw else date.today()
    except ValueError:
        d = date.today()

    # ✅ helper: inicio de semana (lunes)
    def week_start(dt_date: date) -> date:
        return dt_date - timedelta(days=dt_date.weekday())

    if view != "week":
        view = "week"

    start = week_start(d)  # lunes
    week_dates = [start + timedelta(days=i) for i in range(7)]
    prev_date = start - timedelta(days=7)
    next_date = start + timedelta(days=7)

    cfg = get_config_semanal() or {}
    intervalo_minutos = int(cfg.get("intervalo_minutos", 60))
    cupo_maximo = int(cfg.get("cupo_maximo", 10))

    weekday_map = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}

    # ✅ entrenadores para el modal (solo aplica para cliente/admin)
    entrenadores = list(
        users_col.find({"role": "entrenador", "activo": True}, {"username": 1}).sort("username", 1)
    )

    # ✅ turno del cliente para permitir bloques (manana/tarde/full)
    now_ec = datetime.now(TZ_EC)
    turno_cliente = "full"
    if session.get("user_role") == "cliente" and session.get("user_id"):
        try:
            uid = ObjectId(session["user_id"])
            udoc = users_col.find_one({"_id": uid}, {"turno": 1})
            turno_cliente = (udoc or {}).get("turno") or "full"
        except Exception:
            turno_cliente = "full"

    mis_slot_ids = set()
    reserva_por_fecha = {}

    if session.get("user_role") == "cliente" and session.get("user_id"):
        cid = ObjectId(session["user_id"])

        # slots reservados (para pintar "Reservado por ti")
        for r in reservas_col.find({"cliente_id": cid, "estado": "confirmada"}, {"slot_id": 1}):
            sid = r.get("slot_id")
            if sid:
                mis_slot_ids.add(str(sid))

        # reserva por fecha (para cambio de horario / etc)
        fechas_semana = [wd.isoformat() for wd in week_dates]
        cursor = reservas_col.find(
            {"cliente_id": cid, "estado": "confirmada", "fecha": {"$in": fechas_semana}},
            {"slot_id": 1, "fecha": 1}
        )
        for r in cursor:
            fk = r.get("fecha")
            sid = r.get("slot_id")
            if fk and sid:
                reserva_por_fecha[fk] = {"reserva_id": str(r["_id"]), "slot_id": str(sid)}

    week_id = start.isoformat()
    doc_week = semanas_col.find_one({"_id": week_id})

    # ✅ si no existe el documento semanal, lo creas UNA VEZ
    if not doc_week:
        days_arr = []
        for wd in week_dates:
            fecha_key = wd.isoformat()
            day_key = weekday_map[wd.weekday()]
            day_cfg = (cfg.get("dias") or {}).get(day_key, {"activo": False, "plantilla_id": None})

            bloques = resolver_bloques_del_dia(day_cfg)
            cupo_dia = int(day_cfg.get("cupo_maximo", cupo_maximo))

            slots = construir_slots_para_fecha(wd, bloques, intervalo_minutos, cupo_dia)

            for s in slots:
                if "key" not in s:
                    s["key"] = s["inicio"].strftime("%H:%M")
                if "cupo_maximo" not in s:
                    s["cupo_maximo"] = int(cupo_dia)
                if "cupo_restante" not in s:
                    s["cupo_restante"] = int(s["cupo_maximo"])

            days_arr.append({
                "date": fecha_key,
                "dow": day_key,
                "slots": slots
            })

        doc_week = {
            "_id": week_id,
            "week_start": week_id,
            "days": days_arr,
        }
        semanas_col.insert_one(doc_week)

    # =========================
    # ✅ si soy ENTRENADOR, saco mis reservas de la semana
    # =========================
    solo_mis_reservas = (session.get("user_role") == "entrenador" and session.get("user_id"))
    slot_ids_entrenador = set()
    slot_count_entrenador = {}

    if solo_mis_reservas:
        try:
            entrenador_oid = ObjectId(session["user_id"])
        except Exception:
            entrenador_oid = None

        fechas_semana = [wd.isoformat() for wd in week_dates]

        if entrenador_oid:
            pipeline = [
                {"$match": {
                    "entrenador_id": entrenador_oid,
                    "estado": {"$ne": "cancelada"},
                    "fecha": {"$in": fechas_semana},
                }},
                {"$group": {"_id": "$slot_id", "total": {"$sum": 1}}},
            ]
            for row in reservas_col.aggregate(pipeline):
                sid = str(row["_id"])
                slot_ids_entrenador.add(sid)
                slot_count_entrenador[sid] = int(row.get("total", 0))

            entrenadores = []

    # ✅ construir slot_map que usa el HTML
    slot_map = {wd.isoformat(): {} for wd in week_dates}
    all_slots = []
    slot_ids_semana = []

    for day in (doc_week.get("days") or []):
        fecha_key = day.get("date")
        if not fecha_key or fecha_key not in slot_map:
            continue

        # fecha como date()
        try:
            slot_date_obj = datetime.strptime(fecha_key, "%Y-%m-%d").date()
        except Exception:
            continue

        # bloques del día para clasificar slots y ventana
        b1, b2 = _get_blocks_for_date(cfg, slot_date_obj, weekday_map)

        for s in (day.get("slots") or []):
            key = s.get("key") or s["inicio"].strftime("%H:%M")
            slot_id = f"{fecha_key}|{key}"

            if solo_mis_reservas and slot_id not in slot_ids_entrenador:
                continue

            slot_ids_semana.append(slot_id)

            cupo_max = int(s.get("cupo_maximo", cupo_maximo))
            cupo_usado = slot_count_entrenador.get(slot_id, 0) if solo_mis_reservas else 0

            # ✅ calcular bloque (1/2) y reservable por ventana+turno
            block_num = _slot_block_num(s["inicio"], b1, b2)

            reservable = True
            if session.get("user_role") == "cliente":
                primera_vez = (reservas_col.count_documents({"cliente_id": cid, "estado": "confirmada"}) == 0)
                if block_num is None:
                    reservable = False
                elif not _turno_permite(turno_cliente, block_num):
                    reservable = False
                else:
                    ot = _open_time_for_block(cfg, slot_date_obj, block_num, weekday_map)
                    slot_start = s["inicio"]
                    if slot_start.tzinfo is None:
                        slot_start = slot_start.replace(tzinfo=TZ_EC)

                    # ventana abierta y el slot aún no inicia
                    if (ot is None) or (now_ec < ot) or (now_ec >= slot_start):
                        reservable = False

            slot_map[fecha_key][key] = {
                "_id": slot_id,
                "inicio": s["inicio"],
                "fin": s["fin"],
                "cupo_maximo": cupo_max,
                "cupo_usado": cupo_usado,
                

                # ✅ nuevos campos para el template
                "bloque": block_num,          # 1/2/None
                "reservable": reservable,     # True/False (solo cliente)
                "turno_cliente": turno_cliente,  # útil si quieres mostrarlo
            }

            all_slots.append({"inicio": s["inicio"], "fin": s["fin"]})

    # =========================
    # ✅ CONTEO REAL (si NO es entrenador)
    # =========================
    if slot_ids_semana and not solo_mis_reservas:
        slot_ids_semana = list(set(slot_ids_semana))

        pipe_counts = [
            {"$match": {
                "slot_id": {"$in": slot_ids_semana},
                "estado": {"$ne": "cancelada"},
                "cancelada": {"$ne": True},
            }},
            {"$group": {"_id": "$slot_id", "usados": {"$sum": 1}}},
        ]
        counts = {str(x["_id"]): int(x.get("usados", 0)) for x in reservas_col.aggregate(pipe_counts)}

        for fecha_key, m in slot_map.items():
            for k, slot in m.items():
                sid = slot.get("_id")
                slot["cupo_usado"] = counts.get(sid, 0)

    # time_labels
    def to_minute(dt):
        return dt.hour * 60 + dt.minute

    if all_slots:
        min_m = min(to_minute(s["inicio"]) for s in all_slots)
        max_m = max(to_minute(s["fin"]) for s in all_slots)

        min_m = (min_m // intervalo_minutos) * intervalo_minutos
        max_m = ((max_m + intervalo_minutos - 1) // intervalo_minutos) * intervalo_minutos

        min_m = max(0, min_m)
        max_m = min(24 * 60, max_m)
    else:
        min_m = 5 * 60
        max_m = 22 * 60

    time_labels = []
    m = min_m
    while m < max_m:
        hh = m // 60
        mm = m % 60
        time_labels.append(f"{hh:02d}:{mm:02d}")
        m += intervalo_minutos

    return render_template(
        "horarios_publico.html",
        cfg=cfg,
        fecha=d,
        week_dates=week_dates,
        slot_map=slot_map,
        time_labels=time_labels,
        primera_vez = primera_vez,
        intervalo_minutos=intervalo_minutos,
        prev_date=prev_date,
        next_date=next_date,
        reserva_por_fecha=reserva_por_fecha,
        entrenadores=entrenadores,
        mis_slot_ids=mis_slot_ids,
        solo_mis_reservas=solo_mis_reservas,
        turno_cliente=turno_cliente,
        now_ec=now_ec,
    )



@web_bp.get("/admin/horarios")
@login_required(role="admin")
def admin_horarios():
    cfg = get_config_semanal()
    templates = listar_plantillas()
    tpl_map = {str(t.get("_id")): t.get("nombre") for t in templates}

    days_ui = [
        ("mon", "Lunes"), ("tue", "Martes"), ("wed", "Miércoles"),
        ("thu", "Jueves"), ("fri", "Viernes"), ("sat", "Sábado"), ("sun", "Domingo"),
    ]

    return render_template(
        "admin_horarios.html",
        cfg=cfg,
        templates=templates,
        tpl_map=tpl_map,
        days_ui=days_ui
    )


@web_bp.post("/admin/horarios/asignar")
@login_required(role="admin")
def admin_horarios_asignar():
    dias = request.form.getlist("dias")
    plantilla_id = request.form.get("plantilla_id")

    if not dias:
        flash("Selecciona al menos un día.", "danger")
        return redirect(url_for("web.admin_horarios"))

    if not plantilla_id:
        flash("Selecciona un horario.", "danger")
        return redirect(url_for("web.admin_horarios"))

    if not get_plantilla_por_id(plantilla_id):
        flash("El horario seleccionado no existe.", "danger")
        return redirect(url_for("web.admin_horarios"))

    intervalo_raw = (request.form.get("intervalo_minutos") or "").strip()
    cupo_raw      = (request.form.get("cupo_maximo") or "").strip()

    cfg = get_config_semanal() or {}
    intervalo_default = int(cfg.get("intervalo_minutos", 60))
    cupo_default      = int(cfg.get("cupo_maximo", 10))

    dias_dict = cfg.get("dias") or {k: {"activo": False, "plantilla_id": None} for k in DIAS}

    # validar intervalo (global)
    try:
        intervalo_i = int(intervalo_raw) if intervalo_raw else intervalo_default
        if intervalo_i not in (30, 60):
            raise ValueError()
    except Exception:
        flash("Intervalo inválido (solo 30 o 60).", "danger")
        return redirect(url_for("web.admin_horarios"))

    # validar cupo (pero OJO: será por día seleccionado, NO global)
    cupo_i = None
    if cupo_raw:
        try:
            cupo_i = int(cupo_raw)
            if cupo_i < 1:
                raise ValueError()
        except Exception:
            flash("Cupo máximo inválido.", "danger")
            return redirect(url_for("web.admin_horarios"))

    # ✅ asignar plantilla + (opcional) cupo por día
    for dkey in dias:
        dias_dict.setdefault(dkey, {"activo": False, "plantilla_id": None})
        dias_dict[dkey]["activo"] = True
        dias_dict[dkey]["plantilla_id"] = plantilla_id  # o ObjectId si tú guardas oid

        if cupo_i is not None:
            dias_dict[dkey]["cupo_maximo"] = cupo_i  # override SOLO este día

    guardar_config_semanal(intervalo_i, cupo_default, dias_dict)

    flash("Horarios asignados correctamente.", "success")
    return redirect(url_for("web.admin_horarios"))


@web_bp.get("/admin/horarios/crear")
@login_required(role="admin")
def admin_horarios_crear():
    return render_template("admin_horario_crear.html")


@web_bp.post("/admin/horarios/crear")
@login_required(role="admin")
def admin_horarios_crear_post():
    nombre = request.form.get("nombre")
    b1_ini = request.form.get("b1_ini")
    b1_fin = request.form.get("b1_fin")
    b2_ini = request.form.get("b2_ini")
    b2_fin = request.form.get("b2_fin")

    try:
        crear_plantilla(
            nombre=nombre,
            b1_ini=b1_ini,
            b1_fin=b1_fin,
            b2_ini=b2_ini,
            b2_fin=b2_fin,
            creado_por=session.get("username"),
        )
        flash("Horario creado correctamente.", "success")
        return redirect(url_for("web.admin_horarios"))
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("web.admin_horarios_crear"))


@web_bp.post("/admin/horarios/eliminar/<template_id>")
@login_required(role="admin")
def admin_horarios_eliminar(template_id):
    try:
        oid = ObjectId(template_id)
    except Exception:
        flash("ID de horario inválido.", "danger")
        return redirect(url_for("web.admin_horarios"))

    used_days = plantilla_esta_en_uso(oid)
    if used_days:
        day_names = {
            "mon": "Lunes", "tue": "Martes", "wed": "Miércoles", "thu": "Jueves",
            "fri": "Viernes", "sat": "Sábado", "sun": "Domingo"
        }
        usados = ", ".join(day_names.get(d, d) for d in used_days)
        flash(f"No puedes eliminar este horario porque está asignado a: {usados}.", "danger")
        return redirect(url_for("web.admin_horarios"))

    res = eliminar_plantilla(oid)
    if res.deleted_count:
        flash("Horario eliminado correctamente.", "success")
    else:
        flash("No se encontró el horario a eliminar.", "warning")

    return redirect(url_for("web.admin_horarios"))



def _oid(x):
    try:
        return ObjectId(str(x))
    except Exception:
        return None



# RESERVAS
@web_bp.post("/cliente/reservar")
@login_required(role="cliente")
def cliente_reservar():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    semanas_col  = db["horarios_dias"]
    reservas_col = db["reservas"]
    users_col    = db["users"]

    slot_id = (request.form.get("slot_id") or "").strip()  # "YYYY-MM-DD|HH:MM"
    entrenador_id_raw = (request.form.get("entrenador_id") or "").strip()
    fecha_ref = (request.form.get("fecha_ref") or "").strip()

    if not slot_id or "|" not in slot_id:
        flash("Horario inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    fecha_key, slot_key = slot_id.split("|", 1)

    if not entrenador_id_raw:
        flash("Selecciona un entrenador.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    try:
        entrenador_id = ObjectId(entrenador_id_raw)
    except Exception:
        flash("Entrenador inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    entrenador_doc = users_col.find_one(
        {"_id": entrenador_id, "role": "entrenador", "activo": True},
        {"_id": 1, "username": 1}
    )
    if not entrenador_doc:
        flash("Entrenador no encontrado o inactivo.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))
    
    

    try:
        cliente_id = ObjectId(session["user_id"])
    except Exception:
        flash("Sesión inválida.", "danger")
        return redirect(url_for("web.logout"))
    
    primera_vez = (reservas_col.count_documents({"cliente_id": cliente_id, "estado": "confirmada"}) == 0)



    ucli = users_col.find_one({"_id": cliente_id}, {"turno": 1})
    turno_cliente = (ucli or {}).get("turno") or "full"  


    ya_hoy = reservas_col.find_one({
        "cliente_id": cliente_id,
        "estado": "confirmada",
        "fecha": fecha_key,
    })
    if ya_hoy:
        flash("Solo puedes reservar 1 clase por día. Cancela tu reserva para agendar otra.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ✅ evita duplicado exacto (confirmada)
    if reservas_col.find_one({"cliente_id": cliente_id, "slot_id": slot_id, "estado": "confirmada"}):
        flash("Ya tienes una reserva en ese horario.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))
    
    if not primera_vez:
    # ✅ aquí va tu validación de ventana (mañana/tarde)
    # si no cumple -> flash y redirect
        pass


    # week_id (lunes de esa semana)
    try:
        week_id = _week_id_from_date_str(fecha_key)
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    # ==========================================================
    # ✅ validar que el slot exista + leer datos del slot
    # ==========================================================
    doc_week = semanas_col.find_one({"_id": week_id}, {"days": 1})
    if not doc_week:
        flash("Semana no encontrada. Intenta recargar.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    day_doc = None
    for dd in (doc_week.get("days") or []):
        if dd.get("date") == fecha_key:
            day_doc = dd
            break
    if not day_doc:
        flash("Día no encontrado en el horario.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    slot_doc = None
    for ss in (day_doc.get("slots") or []):
        k = ss.get("key") or (ss.get("inicio").strftime("%H:%M") if ss.get("inicio") else None)
        if k == slot_key:
            slot_doc = ss
            break
    if not slot_doc:
        flash("Ese horario no existe.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ==========================================================
    # ✅ NUEVO: validar ventana de apertura y turno (seguro backend)
    # ==========================================================
    cfg = get_config_semanal() or {}

    try:
        slot_date_obj = datetime.strptime(fecha_key, "%Y-%m-%d").date()
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))
    
    weekday_map = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}


    b1, b2 = _get_blocks_for_date(cfg, slot_date_obj, weekday_map)


    slot_start = slot_doc.get("inicio")
    if not slot_start:
        flash("Horario inválido (sin inicio).", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # normaliza tz
    if slot_start.tzinfo is None:
        slot_start = slot_start.replace(tzinfo=TZ_EC)

    block_num = _slot_block_num(slot_start, b1, b2)
    if block_num is None:
        flash("Este horario no está disponible para reservas.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    if not _turno_permite(turno_cliente, block_num):
        flash("Tu turno no permite reservar este bloque.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    now_ec = datetime.now(TZ_EC)
    open_dt = _open_time_for_block(cfg, slot_date_obj, block_num, weekday_map)

    if now_ec < open_dt:
        # mensaje amigable
        flash("Aún no se habilitan reservas para este bloque.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    if now_ec >= slot_start:
        flash("Este horario ya inició. No puedes reservarlo.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))


    cupo_max = int(slot_doc.get("cupo_maximo") or 0)
    if cupo_max <= 0:
        cupo_max = int(cfg.get("cupo_maximo", 10))

    usados = reservas_col.count_documents({
        "slot_id": slot_id,
        "estado": "confirmada",
        "cancelada": {"$ne": True},
    })
    if usados >= cupo_max:
        flash("Ese horario ya no tiene cupos.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    try:
        reservas_col.insert_one({
            "cliente_id": cliente_id,
            "slot_id": slot_id,
            "fecha": fecha_key,
            "entrenador_id": entrenador_id,
            "estado": "confirmada",
            "creado": datetime.now(timezone.utc),
        })
    except Exception:
        flash("No se pudo confirmar la reserva. Intenta nuevamente.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    flash("Reserva confirmada.", "success")
    return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))




@web_bp.post("/cliente/reservas/<reserva_id>/cancelar")
@login_required(role="cliente")
def cliente_cancelar_reserva(reserva_id):
    db = extensions.mongo_db
    semanas_col = db["horarios_dias"]
    reservas_col = db["reservas"]

    try:
        cliente_id = ObjectId(session["user_id"])
        rid = ObjectId(reserva_id)
    except Exception:
        flash("Solicitud inválida.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    reserva = reservas_col.find_one({"_id": rid, "cliente_id": cliente_id, "estado": "confirmada"})
    if not reserva:
        flash("Reserva no encontrada o ya cancelada.", "warning")
        return redirect(url_for("web.cliente_dashboard"))

    slot_id = (reserva.get("slot_id") or "")
    if "|" not in slot_id:
        flash("Reserva inválida.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    fecha_key, slot_key = slot_id.split("|", 1)  # fecha_key="YYYY-MM-DD", slot_key="HH:MM"

    # ✅ REGLA: el cliente solo puede cancelar hasta 2 horas antes del inicio
    TZ_EC = ZoneInfo("America/Guayaquil")
    try:
        inicio_local = datetime.strptime(f"{fecha_key} {slot_key}", "%Y-%m-%d %H:%M").replace(tzinfo=TZ_EC)
    except Exception:
        flash("No se pudo leer la hora de la reserva.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    ahora_local = datetime.now(TZ_EC)
    faltan = inicio_local - ahora_local

    if faltan.total_seconds() <= 0:
        flash("La clase ya inició o ya pasó. No puedes cancelar.", "warning")
        return redirect(url_for("web.cliente_dashboard"))

    if faltan.total_seconds() < 2 * 3600:
        mins = int(faltan.total_seconds() // 60)
        flash(f"Solo puedes cancelar hasta 2 horas antes. Faltan {mins} minuto(s).", "warning")
        return redirect(url_for("web.cliente_dashboard"))

    # ✅ desde aquí sí puede cancelar
    try:
        week_id = _week_id_from_date_str(fecha_key)
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    # ✅ devolver cupo
    semanas_col.update_one(
        {"_id": week_id},
        {"$inc": {"days.$[d].slots.$[s].cupo_restante": 1}},
        array_filters=[
            {"d.date": fecha_key},
            {"s.key": slot_key},
        ]
    )

    # ✅ marcar cancelada
    reservas_col.update_one(
        {"_id": rid},
        {"$set": {"estado": "cancelada", "cancelada_en": datetime.now(timezone.utc)}}
    )

    # clamp defensivo: no pasar de cupo_maximo
    _clamp_slot_restante(db, week_id, fecha_key, slot_key)

    flash("Reserva cancelada. Ya puedes agendar otra clase para ese día.", "success")
    return redirect(url_for("web.cliente_dashboard"))

@web_bp.post("/cliente/reservas/<reserva_id>/cambiar")
@login_required(role="cliente")
def cliente_cambiar_reserva(reserva_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    semanas_col  = db["horarios_dias"]
    reservas_col = db["reservas"]
    users_col    = db["users"]

    # inputs
    slot_id_new = (request.form.get("slot_id") or "").strip()
    entrenador_id_raw = (request.form.get("entrenador_id") or "").strip()
    fecha_ref = (request.form.get("fecha_ref") or "").strip()

    if not slot_id_new or "|" not in slot_id_new:
        flash("Horario inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    try:
        cliente_id = ObjectId(session["user_id"])
        rid = ObjectId(reserva_id)
    except Exception:
        flash("Solicitud inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    # reserva actual
    reserva = reservas_col.find_one({"_id": rid, "cliente_id": cliente_id, "estado": "confirmada"})
    if not reserva:
        flash("Reserva no encontrada o ya cancelada.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    slot_id_old = (reserva.get("slot_id") or "").strip()
    if "|" not in slot_id_old:
        flash("Reserva inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    fecha_old, key_old = slot_id_old.split("|", 1)
    fecha_new, key_new = slot_id_new.split("|", 1)

    # ✅ para “cambiar hora”, obliga mismo día
    if fecha_new != fecha_old:
        flash("Solo puedes cambiar a otra hora del mismo día.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # ✅ regla 2 horas (se basa en la hora ORIGINAL)
    TZ_EC = ZoneInfo("America/Guayaquil")
    try:
        inicio_old_local = datetime.strptime(f"{fecha_old} {key_old}", "%Y-%m-%d %H:%M").replace(tzinfo=TZ_EC)
    except Exception:
        flash("No se pudo leer la hora de la reserva.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    ahora_local = datetime.now(TZ_EC)
    faltan = inicio_old_local - ahora_local
    if faltan.total_seconds() <= 0:
        flash("La clase ya inició o ya pasó. No puedes cambiar.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))
    if faltan.total_seconds() < 2 * 3600:
        mins = int(faltan.total_seconds() // 60)
        flash(f"Solo puedes cambiar hasta 2 horas antes. Faltan {mins} minuto(s).", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # entrenador (si lo quieres obligatorio también al cambiar)
    if not entrenador_id_raw:
        flash("Selecciona un entrenador.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    try:
        entrenador_id = ObjectId(entrenador_id_raw)
    except Exception:
        flash("Entrenador inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    entrenador_doc = users_col.find_one(
        {"_id": entrenador_id, "role": "entrenador", "activo": True},
        {"_id": 1}
    )
    if not entrenador_doc:
        flash("Entrenador no encontrado o inactivo.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # si cambia al mismo slot, no hagas nada
    if slot_id_new == slot_id_old:
        flash("Ya tienes esa reserva.", "info")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # week_id
    try:
        week_id = _week_id_from_date_str(fecha_old)
    except Exception:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # ✅ 1) tomar cupo del NUEVO (si hay)
    dec = semanas_col.update_one(
        {"_id": week_id},
        {"$inc": {"days.$[d].slots.$[s].cupo_restante": -1}},
        array_filters=[
            {"d.date": fecha_new},
            {"s.key": key_new, "s.cupo_restante": {"$gt": 0}},
        ]
    )
    if dec.modified_count == 0:
        flash("Ese horario no existe o ya no tiene cupos.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    # ✅ 2) devolver cupo del VIEJO
    semanas_col.update_one(
        {"_id": week_id},
        {"$inc": {"days.$[d].slots.$[s].cupo_restante": 1}},
        array_filters=[
            {"d.date": fecha_old},
            {"s.key": key_old},
        ]
    )

    # clamps defensivos
    _clamp_slot_restante(db, week_id, fecha_old, key_old)
    _clamp_slot_restante(db, week_id, fecha_new, key_new)

    # ✅ 3) actualizar reserva
    try:
        reservas_col.update_one(
            {"_id": rid, "cliente_id": cliente_id, "estado": "confirmada"},
            {"$set": {
                "slot_id": slot_id_new,
                "fecha": fecha_new,
                "entrenador_id": entrenador_id,
                "cambiado_en": datetime.now(timezone.utc),
                "slot_id_anterior": slot_id_old,
            }}
        )
    except Exception:
        # rollback “mejor esfuerzo”
        semanas_col.update_one(
            {"_id": week_id},
            {"$inc": {"days.$[d].slots.$[s].cupo_restante": 1}},
            array_filters=[{"d.date": fecha_new}, {"s.key": key_new}],
        )
        semanas_col.update_one(
            {"_id": week_id},
            {"$inc": {"days.$[d].slots.$[s].cupo_restante": -1}},
            array_filters=[{"d.date": fecha_old}, {"s.key": key_old, "s.cupo_restante": {"$gt": 0}}],
        )
        _clamp_slot_restante(db, week_id, fecha_old, key_old)
        _clamp_slot_restante(db, week_id, fecha_new, key_new)

        flash("No se pudo cambiar la reserva. Intenta nuevamente.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))

    flash("Reserva cambiada correctamente.", "success")
    return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_old))


@web_bp.get("/cliente/membresia")
@login_required(role="cliente")
def cliente_membresia():
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    ventas_col = db["ventas"]
    clientes_col = db["clientes"]
    noti_col = db["notificaciones"]  # ✅ opcional pero recomendado

    cliente_id = ObjectId(session["user_id"])
    cliente = clientes_col.find_one({"_id": cliente_id})

    # Tomamos la última venta como “membresía actual”
    venta = ventas_col.find_one({"cliente_id": cliente_id}, sort=[("fecha", -1)])
    membresia = (venta or {}).get("membresia")

    ahora = datetime.now(timezone.utc)

    estado = "Sin membresía"
    dias_restantes = None
    alertas = []  # mensajes para UI

    if membresia and membresia.get("fecha_desde") and membresia.get("fecha_hasta"):
        fd = membresia["fecha_desde"]
        fh = membresia["fecha_hasta"]

        # ✅ normalizar tz (por si viene naive)
        if fd.tzinfo is None:
            fd = fd.replace(tzinfo=timezone.utc)
        if fh.tzinfo is None:
            fh = fh.replace(tzinfo=timezone.utc)

        if fh >= ahora:
            estado = "Activa"
            dias_restantes = (fh - ahora).days
        else:
            estado = "Vencida"
            dias_restantes = 0

        # ✅ notificar faltan 5 y 3 días (sin repetir)
        # Guardamos notificación en DB para no spamear cada refresh
        # Clave: cliente_id + tipo + fecha_hasta
        def push_noti(tipo, mensaje):
            existe = noti_col.find_one({
                "cliente_id": cliente_id,
                "tipo": tipo,
                "fecha_hasta": fh,
            })
            if not existe:
                noti_col.insert_one({
                    "cliente_id": cliente_id,
                    "tipo": tipo,
                    "mensaje": mensaje,
                    "fecha_hasta": fh,
                    "creado": ahora,
                    "leido": False,
                })
            alertas.append(mensaje)

        if estado == "Activa" and dias_restantes is not None:
            if dias_restantes == 2:
                push_noti(
                    "membresia_2_dias",
                    "Tu membresía vence en 2 días. Recuerda renovarla."
                )
            elif dias_restantes == 1:
                push_noti(
                    "membresia_1_dia",
                    "⚠️ Tu membresía vence mañana. Se desactivará si no renuevas."
                )


    return render_template(
        "cliente_membresia.html",
        active="cliente_membresia",
        cliente=cliente,
        membresia=membresia,
        estado=estado,
        dias_restantes=dias_restantes,
        alertas=alertas,
    )
    
def _membresia_estado_para_cliente(db, cliente_id: ObjectId):
    from zoneinfo import ZoneInfo
    TZ_EC = ZoneInfo("America/Guayaquil")
    ventas_col = db["ventas"]

    venta = ventas_col.find_one({"cliente_id": cliente_id}, sort=[("fecha", -1)])
    membresia = (venta or {}).get("membresia") if venta else None

    estado = "Sin membresía"
    dias_restantes = None

    if membresia and membresia.get("fecha_hasta"):
        fh = membresia["fecha_hasta"]
        if isinstance(fh, datetime) and fh.tzinfo is None:
            fh = fh.replace(tzinfo=timezone.utc)

        hoy_ec = datetime.now(timezone.utc).astimezone(TZ_EC).date()
        fh_ec = fh.astimezone(TZ_EC).date()
        diff = (fh_ec - hoy_ec).days

        if diff >= 0:
            estado = "Activa"
            dias_restantes = diff
        else:
            estado = "Vencida"
            dias_restantes = None

    return membresia, estado, dias_restantes


@web_bp.before_app_request
def enforce_membresia_cliente():
    # si no hay login, nada
    if not session.get("username"):
        return

    # solo aplica a clientes
    if session.get("user_role") != "cliente":
        return

    db = extensions.mongo_db
    if db is None:
        return

    cliente_id = ObjectId(session["user_id"])
    _, estado, _ = _membresia_estado_para_cliente(db, cliente_id)

    # si está activa, normal
    if estado == "Activa":
        session["membresia_activa"] = True
        return

    # si NO está activa (Vencida o Sin membresía), bloquea todo excepto Membresía/Salir
    session["membresia_activa"] = False

    allowed = {
        "web.cliente_membresia",
        "web.logout",
        "static",
    }

    if request.endpoint and request.endpoint not in allowed:
        return redirect(url_for("web.cliente_membresia_page"))
    
@web_bp.get("/cliente/membresia")
@login_required(role="cliente")
def cliente_membresia_page():
    db = extensions.mongo_db
    cliente_id = ObjectId(session["user_id"])

    membresia, estado_membresia, dias_restantes = _membresia_estado_para_cliente(db, cliente_id)

    return render_template(
        "cliente_membresia.html",
        membresia=membresia,
        estado_membresia=estado_membresia,
        dias_restantes=dias_restantes,
    )
    
    
    

    
# SUBIR PDF

# ✅ asegúrate que este import existe en tu archivo
# from app.utils.pdf_tools import optimizar_pdf


def _allowed_pdf(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "pdf"


def entrenador_tiene_alumno(db, entrenador_oid: ObjectId, cliente_oid: ObjectId) -> bool:
    reservas_col = db["reservas"]
    return reservas_col.count_documents({
        "entrenador_id": entrenador_oid,
        "cliente_id": cliente_oid,
        "estado": {"$ne": "cancelada"},
    }, limit=1) > 0


def safe_delete_or_quarantine(path: str, retries: int = 60, delay: float = 0.2) -> bool:
    for _ in range(retries):
        try:
            if not os.path.exists(path):
                return True
            os.remove(path)
            return True
        except PermissionError:
            pytime.sleep(delay)
        except OSError:
            pytime.sleep(delay)

    try:
        if os.path.exists(path):
            pending = path + ".delete_pending"
            try:
                if os.path.exists(pending):
                    os.remove(pending)
            except Exception:
                pass
            os.replace(path, pending)
    except Exception:
        pass

    return False


def replace_with_retry(src: str, dst: str, retries: int = 60, delay: float = 0.2):
    """
    ✅ Windows: os.replace puede fallar por locks momentáneos (antivirus / indexador).
    """
    last = None
    for _ in range(retries):
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:
            last = e
            pytime.sleep(delay)
        except OSError as e:
            last = e
            pytime.sleep(delay)
    raise last





@web_bp.post("/entrenador/alumno/<cliente_id>/planificacion/subir")
@login_required(role="entrenador")
def subir_planificacion(cliente_id):
    db = extensions.mongo_db
    if db is None:
        raise RuntimeError("mongo_db no está inicializado.")

    plan_col = db["planificaciones"]

    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.horarios_publico"))

    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        flash("Ese alumno no pertenece a tu agenda.", "warning")
        return redirect(url_for("web.horarios_publico"))

    f_pdf = request.files.get("pdf")
    imgs = request.files.getlist("imagenes")  # ✅ nuevo

    # si no subió nada
    if (not f_pdf or not f_pdf.filename) and (not imgs or all((not x or not x.filename) for x in imgs)):
        flash("No seleccionaste archivos para subir.", "warning")
        return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    # validar pdf si viene
    if f_pdf and f_pdf.filename and not _allowed_pdf(f_pdf.filename):
        flash("Solo se permite PDF.", "danger")
        return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    # validar imágenes si vienen
    def _allowed_image(name: str) -> bool:
        name = (name or "").lower()
        return name.endswith((".jpg", ".jpeg", ".png", ".webp", ".gif"))

    clean_imgs = [x for x in (imgs or []) if x and x.filename]
    for im in clean_imgs:
        if not _allowed_image(im.filename):
            flash("Solo se permiten imágenes JPG, PNG, WEBP o GIF.", "danger")
            return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

    base_dir = os.path.join(os.getcwd(), "uploads", "planificaciones", str(entrenador_oid), str(cliente_oid))
    os.makedirs(base_dir, exist_ok=True)

    img_dir = os.path.join(base_dir, "imagenes")
    os.makedirs(img_dir, exist_ok=True)

    old = plan_col.find_one(
        {"entrenador_id": entrenador_oid, "cliente_id": cliente_oid},
        projection={"rel_path": 1, "images": 1}
    ) or {}

    ahora = datetime.now(timezone.utc)

    update_set = {"updated_at": ahora}
    update_on_insert = {"creado": ahora}
    new_images_meta = None

    # ======================
    # ✅ PDF (opcional)
    # ======================
    if f_pdf and f_pdf.filename:
        original_name = secure_filename(f_pdf.filename)

        tmp_dir = os.path.join(base_dir, "_tmp")
        os.makedirs(tmp_dir, exist_ok=True)

        ts_tmp = ahora.strftime("%Y%m%d_%H%M%S_%f")
        tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{original_name}")

        f_pdf.save(tmp_path)
        try:
            f_pdf.close()
        except Exception:
            pass

        ts = ahora.strftime("%Y%m%d_%H%M%S")
        final_name = f"plan_{ts}.pdf"
        final_path = os.path.join(base_dir, final_name)
        final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}.pdf")

        try:
            optimizar_pdf(tmp_path, final_tmp_path)
            replace_with_retry(final_tmp_path, final_path)
        except Exception:
            replace_with_retry(tmp_path, final_path)
        finally:
            safe_delete_or_quarantine(tmp_path)
            safe_delete_or_quarantine(final_tmp_path)

        if not os.path.exists(final_path):
            flash("No se pudo guardar el PDF. Intenta nuevamente.", "danger")
            return redirect(url_for("web.entrenador_alumno_detalle", cliente_id=str(cliente_oid)))

        file_size = os.path.getsize(final_path)
        rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

        # borrar anterior PDF
        if old.get("rel_path"):
            old_abs = os.path.join(os.getcwd(), old["rel_path"])
            if os.path.exists(old_abs) and os.path.abspath(old_abs) != os.path.abspath(final_path):
                safe_delete_or_quarantine(old_abs)

        update_set.update({
            "filename": final_name,
            "rel_path": rel_path,
            "bytes": int(file_size),
        })

    # ======================
    # ✅ IMÁGENES (opcional)
    # ======================
    if clean_imgs:
        # borrar imágenes anteriores si existen (reemplazo total)
        for prev in (old.get("images") or []):
            rp = prev.get("rel_path")
            if rp:
                prev_abs = os.path.join(os.getcwd(), rp)
                if os.path.exists(prev_abs):
                    safe_delete_or_quarantine(prev_abs)

        new_images_meta = []
        for im in clean_imgs:
            safe_name = secure_filename(im.filename)
            ts = ahora.strftime("%Y%m%d_%H%M%S_%f")
            # conservamos extensión original
            ext = os.path.splitext(safe_name)[1].lower() or ".jpg"
            final_img_name = f"img_{ts}{ext}"
            final_img_path = os.path.join(img_dir, final_img_name)

            im.save(final_img_path)
            try:
                im.close()
            except Exception:
                pass

            if not os.path.exists(final_img_path):
                continue

            b = os.path.getsize(final_img_path)
            relp = os.path.relpath(final_img_path, os.getcwd()).replace("\\", "/")
            new_images_meta.append({
                "filename": safe_name,
                "stored_as": final_img_name,
                "rel_path": relp,
                "bytes": int(b),
                "uploaded_at": ahora,
            })

        update_set["images"] = new_images_meta

    # upsert doc
    plan_col.update_one(
        {"entrenador_id": entrenador_oid, "cliente_id": cliente_oid},
        {"$set": update_set, "$setOnInsert": update_on_insert},
        upsert=True
    )

    flash("Planificación guardada.", "success")
    return redirect(url_for("web.entrenador_mis_alumnos", cliente_id=str(cliente_oid)))



@web_bp.get("/planificacion/<plan_id>/download")
@login_required()
def descargar_planificacion(plan_id):
    db = extensions.mongo_db
    plan_col = db["planificaciones"]

    try:
        pid = ObjectId(plan_id)
        uid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = plan_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    role = session.get("user_role")

    # permisos
    if role == "entrenador":
        if doc.get("entrenador_id") != uid:
            abort(403)
    elif role == "cliente":
        if doc.get("cliente_id") != uid:
            abort(403)
    else:
        abort(403)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    return send_file(abs_path, as_attachment=True, download_name=doc.get("filename", "plan.pdf"))


# PUBLICIDAD
@web_bp.get("/publicidad/<pub_id>/media")
@login_required()
def ver_publicidad_media(pub_id):
    db = extensions.mongo_db
    pub_col = db["publicidades"]

    try:
        pid = ObjectId(pub_id)
    except Exception:
        abort(400)

    doc = pub_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    return send_file(abs_path, as_attachment=False)

@web_bp.get("/planificacion/<plan_id>/imagen/<int:idx>")
@login_required()
def ver_plan_imagen(plan_id, idx):
    db = extensions.mongo_db
    plan_col = db["planificaciones"]

    try:
        pid = ObjectId(plan_id)
        uid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = plan_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    role = session.get("user_role")

    # permisos
    if role == "entrenador":
        if doc.get("entrenador_id") != uid:
            abort(403)
    elif role == "cliente":
        if doc.get("cliente_id") != uid:
            abort(403)
    else:
        abort(403)

    imgs = doc.get("images") or []
    if idx < 0 or idx >= len(imgs):
        abort(404)

    abs_path = os.path.join(os.getcwd(), imgs[idx]["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    # inline (para que abra en pestaña y se vea)
    return send_file(abs_path, as_attachment=False)

@web_bp.post("/planificacion/<plan_id>/pdf/eliminar")
@login_required()
def eliminar_plan_pdf(plan_id):
    db = extensions.mongo_db
    plan_col = db["planificaciones"]

    try:
        pid = ObjectId(plan_id)
        uid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = plan_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    role = session.get("user_role")

    # permisos
    if role == "entrenador":
        if doc.get("entrenador_id") != uid:
            abort(403)
        redirect_to = url_for("web.entrenador_alumno_detalle", cliente_id=str(doc.get("cliente_id")))
    elif role == "cliente":
        if doc.get("cliente_id") != uid:
            abort(403)
        # ajusta si tu vista cliente se llama distinto
        redirect_to = url_for("web.cliente_membresia_page")  # o tu página de planificación cliente
    else:
        abort(403)

    # borrar archivo físico
    rel_path = doc.get("rel_path")
    if rel_path:
        abs_path = os.path.join(os.getcwd(), rel_path)
        if os.path.exists(abs_path):
            safe_delete_or_quarantine(abs_path)

    # quitar campos del PDF, NO toca imágenes
    plan_col.update_one(
        {"_id": pid},
        {"$unset": {"filename": "", "rel_path": "", "bytes": ""}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )

    flash("PDF eliminado.", "success")
    return redirect(redirect_to)


@web_bp.post("/planificacion/<plan_id>/imagen/<int:idx>/eliminar")
@login_required()
def eliminar_plan_imagen(plan_id, idx):
    db = extensions.mongo_db
    plan_col = db["planificaciones"]

    try:
        pid = ObjectId(plan_id)
        uid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = plan_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    role = session.get("user_role")

    if role == "entrenador":
        if doc.get("entrenador_id") != uid:
            abort(403)
        redirect_to = url_for("web.entrenador_alumno_detalle", cliente_id=str(doc.get("cliente_id")))
    elif role == "cliente":
        if doc.get("cliente_id") != uid:
            abort(403)
        redirect_to = url_for("web.cliente_membresia_page")  # ajusta a tu pantalla cliente
    else:
        abort(403)

    imgs = doc.get("images") or []
    if idx < 0 or idx >= len(imgs):
        flash("Imagen no encontrada.", "warning")
        return redirect(redirect_to)

    img = imgs[idx]
    relp = img.get("rel_path")
    if relp:
        abs_path = os.path.join(os.getcwd(), relp)
        if os.path.exists(abs_path):
            safe_delete_or_quarantine(abs_path)

    # eliminar del array en Mongo (reconstruyendo lista)
    new_imgs = [x for i, x in enumerate(imgs) if i != idx]

    plan_col.update_one(
        {"_id": pid},
        {"$set": {"images": new_imgs, "updated_at": datetime.now(timezone.utc)}}
    )

    flash("Imagen eliminada.", "success")
    return redirect(redirect_to)

@web_bp.post("/planificacion/<plan_id>/imagenes/eliminar")
@login_required()
def eliminar_plan_imagenes(plan_id):
    db = extensions.mongo_db
    plan_col = db["planificaciones"]

    try:
        pid = ObjectId(plan_id)
        uid = ObjectId(session["user_id"])
    except Exception:
        abort(400)

    doc = plan_col.find_one({"_id": pid})
    if not doc:
        abort(404)

    role = session.get("user_role")

    if role == "entrenador":
        if doc.get("entrenador_id") != uid:
            abort(403)
        redirect_to = url_for("web.entrenador_alumno_detalle", cliente_id=str(doc.get("cliente_id")))
    elif role == "cliente":
        if doc.get("cliente_id") != uid:
            abort(403)
        redirect_to = url_for("web.cliente_membresia_page")  
    else:
        abort(403)

    for img in (doc.get("images") or []):
        relp = img.get("rel_path")
        if relp:
            abs_path = os.path.join(os.getcwd(), relp)
            if os.path.exists(abs_path):
                safe_delete_or_quarantine(abs_path)

    plan_col.update_one(
        {"_id": pid},
        {"$unset": {"images": ""}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )

    flash("Imágenes eliminadas.", "success")
    return redirect(redirect_to)
