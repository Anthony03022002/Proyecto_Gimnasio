import calendar
from functools import wraps
import os
import re
import shutil
from bson import ObjectId
from flask import abort, jsonify, render_template, redirect, send_file, url_for, request, session, flash
from . import web_bp
from app.services.user_service import get_users_collection, create_cajero, list_cajeros, reset_password_cliente, update_cajero, reset_password_cajero, delete_cajero, create_entrenador, list_entrenadores, update_entrenador, reset_password_entrenador, delete_entrenador
from app.extensions import bcrypt
from app.services.ventas_service import crear_venta, listar_ventas_por_cajero, resumen_ventas_hoy_por_cajero, get_ventas_collection
from datetime import date, datetime, timedelta, timezone
import time as pytime
import app.extensions as extensions
from app.services.horarios_semanales import (
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


def _parse_date_yyyy_mm_dd(s: str):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.strip())  # 'YYYY-MM-DD'
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
    if "user_role" in session:
        return redirect(url_for(f"web.{session['user_role']}_dashboard"))
    return redirect(url_for("web.login"))


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

    total_clientes = clientes.count_documents({})
    total_entrenadores = users.count_documents({"role": "entrenador"})
    total_cajeros = users.count_documents({"role": "cajero"})

    ahora = datetime.now(timezone.utc)
    inicio = ahora.replace(hour=0, minute=0, second=0, microsecond=0)
    fin = ahora.replace(hour=23, minute=59, second=59, microsecond=999000)

    ventas_hoy = ventas.count_documents({"fecha": {"$gte": inicio, "$lte": fin}})

    pipeline = [
        # ✅ SOLO HOY
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
        total_entrenadores=total_entrenadores,
        total_cajeros=total_cajeros,
        ventas_hoy=ventas_hoy,
        ultimas_ventas=ultimas_ventas,
    )


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

    fecha_desde_dt = datetime.combine(fecha_desde_date, pytime.min)
    fecha_hasta_dt = datetime.combine(fecha_hasta_date, pytime.min)

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


    f = request.files.get("foto")
    if not f or not f.filename:
        flash("No se subió ninguna imagen.", "warning")
        return redirect(url_for("web.admin_publicidad"))

    # ✅ valida formato (usa tu helper allowed_image si ya lo tienes)
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in {"jpg", "jpeg", "png", "webp"}:
        flash("Formato no permitido. Usa JPG, PNG o WEBP.", "danger")
        return redirect(url_for("web.admin_publicidad"))

    base_dir = os.path.join(os.getcwd(), "uploads", "publicidad")
    tmp_dir  = os.path.join(base_dir, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    ts_tmp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    original_name = secure_filename(f.filename)
    tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{original_name}")
    f.save(tmp_path)
    try:
        f.close()
    except Exception:
        pass

    # ✅ guardar como JPG optimizado
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    final_name = f"pub_{ts}.jpg"
    final_path = os.path.join(base_dir, final_name)
    final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}.jpg")

    try:
        # optimiza (max_side y quality ajustables)
        optimizar_imagen(tmp_path, final_tmp_path, max_side=1600, quality=82)
        replace_with_retry(final_tmp_path, final_path)
    except Exception:
        # último recurso: mover el original tal cual
        replace_with_retry(tmp_path, final_path)
    finally:
        safe_delete_or_quarantine(tmp_path)
        safe_delete_or_quarantine(final_tmp_path)

    if not os.path.exists(final_path):
        flash("No se pudo guardar la publicidad.", "danger")
        return redirect(url_for("web.admin_publicidad"))

    file_size = os.path.getsize(final_path)
    rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

    # ✅ por defecto: NO activar automáticamente (o si quieres, lo activamos)
    pub_col.insert_one({
        "filename": final_name,
        "rel_path": rel_path,
        "titulo": titulo or "Publicidad",
        "bytes": int(file_size),
        "activo": False,
        "creado": datetime.now(timezone.utc),
    })

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

    # ✅ solo 1 activa a la vez
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

    return render_template(
        "dashboard_cajero.html",
        ventas=ventas,
        resumen_hoy=resumen_hoy,
        ultima_venta=ultima_venta,

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

    if not cliente_id:
        flash("Selecciona un cliente.", "danger")
        return redirect(url_for("web.cajero_renovar"))

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
        projection={"filename": 1, "bytes": 1, "updated_at": 1, "creado": 1}
    )

    return render_template(
        "alumno_detalle.html",
        alumno=alumno,
        cliente_id=str(cliente_oid),
        plan=plan,
        active="entrenador_mis_alumnos",
    )



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

    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("web.logout"))

    cliente_id = ObjectId(user_id)

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

    # ✅ Solo disparar notificaciones si está ACTIVA
    if estado_membresia == "Activa" and dias_restantes is not None and fh is not None:
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

    # ✅ Si no tocó 5 o 3, muestra últimas notis activas SOLO si sigue activa
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
    

    return render_template(
        "dashboard_cliente.html",
        cliente=cliente,
        membresia=membresia,
        estado_membresia=estado_membresia,
        dias_restantes=dias_restantes,
        alertas_membresia=alertas_membresia,
        clases_proximas=clases_prox,
        clases_pasadas=clases_pas,
    )


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
        projection={"filename": 1, "bytes": 1, "updated_at": 1, "creado": 1}
    )

    fotos = list(fotos_col.find(
        {"cliente_id": cliente_oid},
        projection={"filename": 1, "bytes": 1, "creado": 1}
    ).sort("creado", -1).limit(60))

    return render_template(
        "cliente_progreso.html",
        plan_actual=plan_actual,
        fotos=fotos,
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

    f = request.files.get("foto")
    if not f or not f.filename:
        flash("No se subió ninguna imagen.", "warning")
        return redirect(url_for("web.cliente_progreso"))

    if not allowed_image(f.filename):
        flash("Formato no permitido. Usa JPG, PNG o WEBP.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    base_dir = os.path.join(os.getcwd(), "uploads", "progreso", str(cliente_oid))
    os.makedirs(base_dir, exist_ok=True)

    tmp_dir = os.path.join(base_dir, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    original_name = secure_filename(f.filename)
    ts_tmp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{original_name}")

    f.save(tmp_path)
    try:
        f.close()
    except Exception:
        pass

    # ✅ siempre guardamos como JPG optimizado
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    final_name = f"foto_{ts}.jpg"
    final_path = os.path.join(base_dir, final_name)

    final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}.jpg")

    try:
        # optimiza -> final_tmp
        optimizar_imagen(tmp_path, final_tmp_path, max_side=1600, quality=82)
        # mueve con retry (windows locks)
        replace_with_retry(final_tmp_path, final_path)
    except Exception:
        # si falla optimización, guardamos original tal cual (pero OJO: puede ser PNG pesado)
        # mejor guardarlo igual como jpg simple:
        try:
            optimizar_imagen(tmp_path, final_tmp_path, max_side=2000, quality=85)
            replace_with_retry(final_tmp_path, final_path)
        except Exception:
            # último recurso: guarda el archivo original con su extensión
            # (pero así podría ser pesado)
            replace_with_retry(tmp_path, final_path)
    finally:
        safe_delete_or_quarantine(tmp_path)
        safe_delete_or_quarantine(final_tmp_path)

    if not os.path.exists(final_path):
        flash("No se pudo guardar la imagen. Intenta nuevamente.", "danger")
        return redirect(url_for("web.cliente_progreso"))

    file_size = os.path.getsize(final_path)
    rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

    fotos_col.insert_one({
        "cliente_id": cliente_oid,
        "filename": final_name,
        "rel_path": rel_path,
        "bytes": int(file_size),
        "creado": datetime.now(timezone.utc),
    })

    flash(f"Foto subida y optimizada ({file_size/1024/1024:.2f} MB).", "success")
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

    # ✅ permiso: solo el dueño
    if doc.get("cliente_id") != cliente_oid:
        abort(403)

    abs_path = os.path.join(os.getcwd(), doc["rel_path"])
    if not os.path.exists(abs_path):
        abort(404)

    # inline para mostrar en galería (no descargar)
    return send_file(abs_path, as_attachment=False)




# Horarios Semanales

@web_bp.get("/horarios")
@login_required()
def horarios_publico():
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

    cfg = get_config_semanal()
    intervalo_minutos = int(cfg.get("intervalo_minutos", 60))
    cupo_maximo = int(cfg.get("cupo_maximo", 10))

    weekday_map = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}

    # ✅ entrenadores para el modal (solo aplica para cliente/admin)
    entrenadores = list(
        users_col.find({"role": "entrenador", "activo": True}, {"username": 1}).sort("username", 1)
    )

    # ✅ slots reservados por mí (para “Reservado por ti”) cuando soy CLIENTE
    mis_slot_ids = set()
    if session.get("user_role") == "cliente" and session.get("user_id"):
        cid = ObjectId(session["user_id"])
        for r in reservas_col.find({"cliente_id": cid, "estado": "confirmada"}, {"slot_id": 1}):
            sid = r.get("slot_id")
            if sid:
                mis_slot_ids.add(str(sid))

    # helper: inicio de semana (lunes)
    def week_start(dt_date: date) -> date:
        return dt_date - timedelta(days=dt_date.weekday())

    if view != "week":
        view = "week"

    start = week_start(d)  # lunes
    week_dates = [start + timedelta(days=i) for i in range(7)]
    prev_date = start - timedelta(days=7)
    next_date = start + timedelta(days=7)

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
            slots = construir_slots_para_fecha(wd, bloques, intervalo_minutos, cupo_maximo)

            for s in slots:
                if "key" not in s:
                    s["key"] = s["inicio"].strftime("%H:%M")
                if "cupo_maximo" not in s:
                    s["cupo_maximo"] = int(cupo_maximo)
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
    # ✅ NUEVO: si soy ENTRENADOR, saco mis reservas de la semana
    # =========================
    solo_mis_reservas = (session.get("user_role") == "entrenador" and session.get("user_id"))
    slot_ids_entrenador = set()
    slot_count_entrenador = {}  # slot_id -> total reservas

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

            # opcional: en esta vista el modal de "elegir entrenador" no tiene sentido
            entrenadores = []  # o déjalo como estaba si lo usas en otra parte

    # ✅ construir slot_map que usa el HTML (por día -> por hora)
    slot_map = {wd.isoformat(): {} for wd in week_dates}
    all_slots = []

    for day in (doc_week.get("days") or []):
        fecha_key = day.get("date")
        if not fecha_key or fecha_key not in slot_map:
            continue

        for s in (day.get("slots") or []):
            key = s.get("key") or s["inicio"].strftime("%H:%M")

            slot_id = f"{fecha_key}|{key}"  # ✅ mismo formato que reservas.slot_id

            # ✅ NUEVO: si soy entrenador -> solo mostrar slots donde tengo reservas
            if solo_mis_reservas and slot_id not in slot_ids_entrenador:
                continue

            cupo_max = int(s.get("cupo_maximo", cupo_maximo))
            cupo_rest = int(s.get("cupo_restante", cupo_max))
            cupo_usado = cupo_max - cupo_rest

            # ✅ NUEVO: si soy entrenador, cupo_usado = cantidad real de reservas del slot
            if solo_mis_reservas:
                cupo_usado = slot_count_entrenador.get(slot_id, 0)

            slot_map[fecha_key][key] = {
                "_id": slot_id,              # ✅ slot_id para modal/POST
                "inicio": s["inicio"],
                "fin": s["fin"],
                "cupo_maximo": cupo_max,
                "cupo_usado": cupo_usado,
            }

            all_slots.append({"inicio": s["inicio"], "fin": s["fin"]})

    # time_labels igual que antes (pero basado en slots reales del doc semanal)
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
        intervalo_minutos=intervalo_minutos,
        prev_date=prev_date,
        next_date=next_date,
        entrenadores=entrenadores,
        mis_slot_ids=mis_slot_ids,

        # ✅ NUEVO: para mostrar botón "Ver alumnos" en el template
        solo_mis_reservas=solo_mis_reservas,
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

    asignar_plantilla_a_dias(dias, plantilla_id)

    intervalo_raw = request.form.get("intervalo_minutos")
    cupo_raw = request.form.get("cupo_maximo")

    cfg = get_config_semanal()
    dias_dict = cfg.get("dias") or {k: {"activo": False, "plantilla_id": None} for k in DIAS}

    try:
        intervalo_i = int(intervalo_raw) if intervalo_raw else int(cfg.get("intervalo_minutos", 60))
        cupo_i = int(cupo_raw) if cupo_raw else int(cfg.get("cupo_maximo", 10))

        if intervalo_i not in (30, 60):
            raise ValueError()
        if cupo_i < 1:
            raise ValueError()

        cfg2 = get_config_semanal()
        guardar_config_semanal(intervalo_i, cupo_i, cfg2.get("dias") or dias_dict)

    except ValueError:
        flash("Intervalo o cupo inválido.", "danger")
        return redirect(url_for("web.admin_horarios"))

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

    semanas_col  = db["horarios_dias"]   # docs semanales
    reservas_col = db["reservas"]
    users_col    = db["users"]           # ✅ NUEVO: para validar entrenador

    slot_id = (request.form.get("slot_id") or "").strip()   # "YYYY-MM-DD|HH:MM"
    entrenador_id_raw = (request.form.get("entrenador_id") or "").strip()  # ✅ AHORA id
    fecha_ref = (request.form.get("fecha_ref") or "").strip()

    if not slot_id or "|" not in slot_id:
        flash("Horario inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    fecha_key, slot_key = slot_id.split("|", 1)  # fecha_key="YYYY-MM-DD", slot_key="HH:MM"

    if not entrenador_id_raw:
        flash("Selecciona un entrenador.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ✅ convertir entrenador_id a ObjectId
    try:
        entrenador_id = ObjectId(entrenador_id_raw)
    except Exception:
        flash("Entrenador inválido.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ✅ validar que exista y sea entrenador activo
    entrenador_doc = users_col.find_one(
        {"_id": entrenador_id, "role": "entrenador", "activo": True},
        {"_id": 1, "username": 1}
    )
    if not entrenador_doc:
        flash("Entrenador no encontrado o inactivo.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # cliente_id
    try:
        cliente_id = ObjectId(session["user_id"])
    except Exception:
        flash("Sesión inválida.", "danger")
        return redirect(url_for("web.logout"))

    # ✅ REGLA: 1 reserva confirmada por día
    ya_hoy = reservas_col.find_one({
        "cliente_id": cliente_id,
        "estado": "confirmada",
        "fecha": fecha_key,
    })
    if ya_hoy:
        flash("Solo puedes reservar 1 clase por día. Cancela tu reserva para agendar otra.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ✅ evitar duplicado exacto (misma hora)
    if reservas_col.find_one({"cliente_id": cliente_id, "slot_id": slot_id, "estado": "confirmada"}):
        flash("Ya tienes una reserva en ese horario.", "warning")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # week_id (lunes de esa fecha)
    try:
        d = datetime.strptime(fecha_key, "%Y-%m-%d").date()
    except ValueError:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_ref or None))

    week_start = d - timedelta(days=d.weekday())
    week_id = week_start.isoformat()

    # ✅ descontar cupo en doc semanal
    res = semanas_col.update_one(
        {"_id": week_id},
        {"$inc": {"days.$[d].slots.$[s].cupo_restante": -1}},
        array_filters=[
            {"d.date": fecha_key},
            {"s.key": slot_key, "s.cupo_restante": {"$gt": 0}},
        ]
    )

    if res.modified_count == 0:
        flash("Ese horario no existe o ya no tiene cupos.", "danger")
        return redirect(url_for("web.horarios_publico", view="week", fecha=fecha_key))

    # ✅ crear reserva guardando entrenador_id
    reservas_col.insert_one({
        "cliente_id": cliente_id,
        "slot_id": slot_id,
        "fecha": fecha_key,
        "entrenador_id": entrenador_id,          # ✅ AQUÍ
        # opcional: guardar username para no hacer lookup después
        # "entrenador_username": entrenador_doc.get("username"),
        "estado": "confirmada",
        "creado": datetime.now(timezone.utc),
    })

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

    fecha_key, slot_key = slot_id.split("|", 1)

    try:
        d = datetime.strptime(fecha_key, "%Y-%m-%d").date()
    except ValueError:
        flash("Fecha inválida.", "danger")
        return redirect(url_for("web.cliente_dashboard"))

    week_start = d - timedelta(days=d.weekday())
    week_id = week_start.isoformat()

    semanas_col.update_one(
        {"_id": week_id},
        {"$inc": {"days.$[d].slots.$[s].cupo_restante": 1}},
        array_filters=[
            {"d.date": fecha_key},
            {"s.key": slot_key},
        ]
    )

    reservas_col.update_one(
        {"_id": rid},
        {"$set": {"estado": "cancelada", "cancelada_en": datetime.now(timezone.utc)}}
    )

    flash("Reserva cancelada. Ya puedes agendar otra clase para ese día.", "success")
    return redirect(url_for("web.cliente_dashboard"))

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
            if dias_restantes <= 5 and dias_restantes > 3:
                push_noti(
                    "membresia_5_dias",
                    f"Tu membresía vence en {dias_restantes} días. Recuerda renovarla."
                )
            elif dias_restantes <= 3 and dias_restantes >= 0:
                push_noti(
                    "membresia_3_dias",
                    f"⚠️ Tu membresía vence en {dias_restantes} días. Se desactivará si no renuevas."
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

    # entrenador logueado
    try:
        entrenador_oid = ObjectId(session["user_id"])
        cliente_oid = ObjectId(cliente_id)
    except Exception:
        flash("ID inválido.", "danger")
        return redirect(url_for("web.horarios_publico"))

    # seguridad: alumno con reservas del entrenador
    if not entrenador_tiene_alumno(db, entrenador_oid, cliente_oid):
        flash("Ese alumno no pertenece a tu agenda.", "warning")
        return redirect(url_for("web.horarios_publico"))

    f = request.files.get("pdf")
    if not f or not f.filename:
        flash("No se subió ningún archivo.", "warning")
        return redirect(url_for("web.horarios_publico"))

    if not _allowed_pdf(f.filename):
        flash("Solo se permite PDF.", "danger")
        return redirect(url_for("web.horarios_publico"))

    # carpeta destino
    base_dir = os.path.join(os.getcwd(), "uploads", "planificaciones", str(entrenador_oid), str(cliente_oid))
    os.makedirs(base_dir, exist_ok=True)

    # buscar planificación anterior (para borrarla luego)
    old = plan_col.find_one(
        {"entrenador_id": entrenador_oid, "cliente_id": cliente_oid},
        projection={"rel_path": 1}
    )

    # tmp dir
    tmp_dir = os.path.join(base_dir, "_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    # tmp único
    original_name = secure_filename(f.filename)
    ts_tmp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    tmp_path = os.path.join(tmp_dir, f"{ts_tmp}__{original_name}")

    # guardar temporal
    f.save(tmp_path)
    try:
        f.close()
    except Exception:
        pass

    # ✅ FINAL con nombre único
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    final_name = f"plan_{ts}.pdf"
    final_path = os.path.join(base_dir, final_name)

    # optimiza hacia final_tmp y luego lo mueves a final_path
    final_tmp_path = os.path.join(tmp_dir, f"__final__{ts_tmp}.pdf")

    try:
        # ✅ tu optimizar_pdf YA NO debe usar linear=True (eso rompe en tu PyMuPDF)
        optimizar_pdf(tmp_path, final_tmp_path)

        # ✅ mover con retry (windows locks)
        replace_with_retry(final_tmp_path, final_path)

    except Exception:
        # si falla optimización: usa el original como final (con retry)
        replace_with_retry(tmp_path, final_path)

    finally:
        safe_delete_or_quarantine(tmp_path)
        safe_delete_or_quarantine(final_tmp_path)

    # validar final
    if not os.path.exists(final_path):
        flash("No se pudo guardar el PDF. Intenta nuevamente.", "danger")
        return redirect(url_for("web.horarios_publico"))

    file_size = os.path.getsize(final_path)
    rel_path = os.path.relpath(final_path, os.getcwd()).replace("\\", "/")

    # borrar anterior (si existe y es distinto)
    if old and old.get("rel_path"):
        old_abs = os.path.join(os.getcwd(), old["rel_path"])
        if os.path.exists(old_abs) and os.path.abspath(old_abs) != os.path.abspath(final_path):
            safe_delete_or_quarantine(old_abs)

    # ✅ upsert: 1 planificación por alumno (por entrenador) en Mongo
    plan_col.update_one(
        {"entrenador_id": entrenador_oid, "cliente_id": cliente_oid},
        {
            "$set": {
                "filename": final_name,
                "rel_path": rel_path,
                "bytes": int(file_size),
                "updated_at": datetime.now(timezone.utc),
            },
            "$setOnInsert": {
                "creado": datetime.now(timezone.utc),
            }
        },
        upsert=True
    )

    flash(f"Planificación subida y optimizada ({file_size/1024/1024:.2f} MB).", "success")
    return redirect(url_for("web.horarios_publico"))


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


#PUBLICIDAD
@web_bp.get("/publicidad/<pub_id>/img")
@login_required()
def ver_publicidad_img(pub_id):
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

    # inline para mostrar
    return send_file(abs_path, as_attachment=False)