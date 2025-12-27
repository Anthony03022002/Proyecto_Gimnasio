import calendar
from functools import wraps
from bson import ObjectId
from flask import render_template, redirect, url_for, request, session, flash
from . import web_bp
from app.services.user_service import get_users_collection, create_cajero, list_cajeros, update_cajero, reset_password_cajero, delete_cajero, create_entrenador, list_entrenadores, update_entrenador, reset_password_entrenador, delete_entrenador
from app.extensions import bcrypt
from app.services.ventas_service import crear_venta, listar_ventas_por_cajero, resumen_ventas_hoy_por_cajero, get_ventas_collection
from datetime import date, datetime, timedelta, time, timezone
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

    session["user_id"] = str(user["_id"]) 
    session["username"] = user["username"]
    session["user_role"] = user["role"]

    role_name = session.get("user_role")
    if not role_name:
        return redirect(url_for("web.login"))
    return redirect(url_for(f"web.{role_name}_dashboard"))



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
            "vendedor_username": 1,
            "membresia": 1,
            "cliente_nombre": "$cliente.nombre",
            "cliente_identificacion": "$cliente.identificacion",
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
    password = request.form.get("password")

    if not username or not password:
        flash("Usuario y contraseña son obligatorios.", "danger")
        return redirect(url_for("web.admin_cajeros"))

    try:
        create_cajero(username=username, password=password, nombre=nombre)
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

    try:
        update_cajero(cajero_id, username=username, nombre=nombre)
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
        for c in clientes_col.find({"_id": {"$in": cliente_ids_tabla}}, {"nombre": 1}):
            clientes_map[str(c["_id"])] = c.get("nombre") or "-"

    for u in usuarios:
        if u.get("role") == "cliente":
            cid = u.get("cliente_id") or u.get("_id")
            u["nombre_mostrar"] = clientes_map.get(str(cid), "-")
        else:
            u["nombre_mostrar"] = u.get("nombre") or "-"

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

    nombre = (request.form.get("nombre") or "").strip()
    cliente_nombre = (request.form.get("cliente_nombre") or "").strip()

    try:
        if not username:
            raise ValueError("Username es obligatorio.")
        if role not in ("admin", "cajero", "entrenador", "cliente"):
            raise ValueError("Rol inválido.")

        if username != u.get("username"):
            if users_col.find_one({"username": username, "_id": {"$ne": oid}}):
                raise ValueError("Ese username ya está en uso.")

        update_user = {"username": username, "role": role}

        if new_password:
            if len(new_password) < 6:
                raise ValueError("La contraseña debe tener al menos 6 caracteres.")
            update_user["password"] = bcrypt.generate_password_hash(new_password).decode("utf-8")
            update_user["must_change_password"] = False  

        if role != "cliente":
            update_user["nombre"] = nombre 
            

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
                    {"$set": {"nombre": cliente_nombre}},
                    upsert=True
                )

        flash("Usuario actualizado correctamente.", "success")

    except Exception as e:
        flash(str(e), "danger")

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

    try:
        if not username or not password:
            raise ValueError("Usuario y contraseña son obligatorios.")
        if len(password) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres.")
        create_entrenador(username, password, nombre=nombre)
        flash("Entrenador creado correctamente.", "success")
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for("web.admin_entrenadores"))


@web_bp.post("/admin/entrenadores/editar/<entrenador_id>")
@login_required(role="admin")
def admin_entrenadores_edit(entrenador_id):
    username = (request.form.get("username") or "").strip()
    nombre = (request.form.get("nombre") or "").strip() or None

    try:
        if not username:
            raise ValueError("Usuario es obligatorio.")
        update_entrenador(entrenador_id, username=username, nombre=nombre)
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

def _utcnow():
    return datetime.now(timezone.utc)

@web_bp.get("/admin/clientes")
@login_required(role="admin")
def admin_clientes():
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    ventas_col = db["ventas"]

    q = (request.args.get("q") or "").strip()

    match = {}
    if q:
        match["$or"] = [
            {"nombre": {"$regex": q, "$options": "i"}},
            {"identificacion": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"telefono": {"$regex": q, "$options": "i"}},
        ]

    ahora = _utcnow()

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

    if not nombre or not identificacion:
        flash("Nombre e identificación son obligatorios.", "danger")
        return redirect(url_for("web.admin_clientes"))

    clientes_col.update_one(
        {"_id": oid},
        {"$set": {
            "nombre": nombre,
            "identificacion": identificacion,
            "email": email,
            "telefono": telefono,
        }}
    )

    flash("Cliente actualizado.", "success")
    return redirect(url_for("web.admin_clientes"))


@web_bp.post("/admin/clientes/estado/<cliente_id>")
@login_required(role="admin")
def admin_clientes_estado(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    try:
        oid = ObjectId(str(cliente_id))
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.admin_clientes"))

    activo_raw = (request.form.get("activo") or "").strip()  
    activo = True if activo_raw == "1" else False

    clientes_col.update_one({"_id": oid}, {"$set": {"activo": activo}})

    flash("Estado actualizado.", "success")
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
    telefono = request.form.get("telefono") or None

    meses_raw = request.form.get("meses") or "1"
    fecha_desde_raw = request.form.get("fecha_desde")
    fecha_hasta_raw = request.form.get("fecha_hasta")

    if not identificacion or not nombre:
        flash("Identificación y nombre del cliente son obligatorios.", "danger")
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

    fecha_desde_dt = datetime.combine(fecha_desde_date, time.min)
    fecha_hasta_dt = datetime.combine(fecha_hasta_date, time.min)

    cliente_data = {
        "identificacion": identificacion,
        "nombre": nombre,
        "email": email,
        "telefono": telefono,
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


# CAJERO
@web_bp.get("/cajero")
@login_required(role="cajero")
def cajero_dashboard():
    username = session.get("username")

    ventas = listar_ventas_por_cajero(username, limit=10)
    resumen_hoy = resumen_ventas_hoy_por_cajero(username)
    ultima_venta = ventas[0] if ventas else None

    return render_template(
        "dashboard_cajero.html",
        ventas=ventas,
        resumen_hoy=resumen_hoy,
        ultima_venta=ultima_venta,
    )


@web_bp.get("/cajero/clientes")
@login_required(role="cajero")
def cajero_clientes():
    db = extensions.mongo_db
    ventas_col = db["ventas"]
    clientes_col = db["clientes"]
    users_col = db["users"]

    username = session.get("username")

    # 1) ids de clientes relacionados a tus ventas
    cliente_ids = ventas_col.distinct("cliente_id", {"vendedor_username": username})
    cliente_ids = [cid for cid in cliente_ids if cid]

    clientes = []

    for cid in cliente_ids:
        # 2) Traer datos del cliente
        c = clientes_col.find_one({"_id": cid}) or {}
        u = users_col.find_one({"_id": cid}, {"username": 1}) or {}

        # ✅ 3) AQUÍ VA lo que preguntaste: última membresía desde ventas
        ultima = ventas_col.find_one(
            {"cliente_id": cid},
            sort=[("fecha", -1)],
            projection={"membresia": 1, "fecha": 1}
        )
        memb = ultima.get("membresia") if ultima else None
        fh = _to_date(memb.get("fecha_hasta")) if isinstance(memb, dict) else None

        # 4) Calcular estado con tu lógica + bloqueo manual
        bloqueado = bool(c.get("bloqueado_manual", False))
        hoy = date.today()

        if bloqueado:
            activo = False
            estado = "Suspendido"
        else:
            if not fh:
                activo = False
                estado = "Sin membresía"
            elif fh >= hoy:
                activo = True
                estado = "Activo"
            else:
                activo = False
                estado = "Vencido"

        # (opcional) auto-sync solo guardando activo (sin guardar fechas)
        clientes_col.update_one({"_id": cid}, {"$set": {"activo": activo}})

        clientes.append({
            "_id": cid,
            "nombre": c.get("nombre", ""),
            "telefono": c.get("telefono", ""),
            "username": u.get("username", ""),
            "estado": estado,
            "activo": activo,
            "bloqueado_manual": bloqueado,
            "fecha_hasta": fh,  # solo para mostrar
        })

    return render_template("cajero_clientes.html", clientes=clientes)


@web_bp.get("/cajero/clientes/<cliente_id>/editar")
@login_required(role="cajero")
def cajero_cliente_editar(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    oid = _oid(cliente_id)
    if not oid:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    # seguridad: que sea cliente del cajero
    if not _cajero_owns_cliente(db, session.get("username"), oid):
        flash("No tienes permiso para editar este cliente.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    cliente = clientes_col.find_one({"_id": oid})
    if not cliente:
        flash("Cliente no encontrado.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    return render_template("cajero_cliente_form.html", mode="edit", cliente=cliente)


@web_bp.post("/cajero/clientes/<cliente_id>/editar")
@login_required(role="cajero")
def cajero_cliente_editar_post(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    oid = _oid(cliente_id)
    if not oid:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    if not _cajero_owns_cliente(db, session.get("username"), oid):
        flash("No tienes permiso para editar este cliente.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    nombre = (request.form.get("nombre") or "").strip()
    telefono = (request.form.get("telefono") or "").strip()
    email = (request.form.get("email") or "").strip()
    identificacion = (request.form.get("identificacion") or "").strip()
    activo = True if request.form.get("activo") == "on" else False

    if not nombre:
        flash("El nombre es obligatorio.", "danger")
        return redirect(url_for("web.cajero_cliente_editar", cliente_id=cliente_id))

    clientes_col.update_one(
        {"_id": oid},
        {"$set": {
            "nombre": nombre,
            "telefono": telefono,
            "email": email,
            "identificacion": identificacion,
            "activo": activo
        }}
    )

    flash("Cliente actualizado.", "success")
    return redirect(url_for("web.cajero_clientes"))


@web_bp.post("/cajero/clientes/<cliente_id>/eliminar")
@login_required(role="cajero")
def cajero_cliente_eliminar(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]
    ventas_col = db["ventas"]

    oid = _oid(cliente_id)
    if not oid:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    if not _cajero_owns_cliente(db, session.get("username"), oid):
        flash("No tienes permiso para eliminar este cliente.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    # ✅ recomendado: no borrar, solo desactivar
    clientes_col.update_one({"_id": oid}, {"$set": {"activo": False}})
    flash("Cliente desactivado.", "warning")
    return redirect(url_for("web.cajero_clientes"))


def as_date(x):
    if x is None:
        return None
    if isinstance(x, datetime):
        return x.date()
    if isinstance(x, date):
        return x
    return None

def as_datetime(x):
    """
    Convierte date/datetime a datetime a las 00:00:00.
    """
    if x is None:
        return None
    if isinstance(x, datetime):
        return x
    if isinstance(x, date):
        return datetime.combine(x, time.min)
    return None

def sync_cliente_activo_por_membresia(db, cliente_id):
    clientes_col = db["clientes"]
    ventas_col = db["ventas"]

    hoy = date.today()

    cliente = clientes_col.find_one({"_id": cliente_id}, {"bloqueado_manual": 1})
    if not cliente:
        return None

    bloqueado = bool(cliente.get("bloqueado_manual", False))

    ultima = ventas_col.find_one(
        {"cliente_id": cliente_id},
        sort=[("fecha", -1)],
        projection={"membresia": 1}
    )

    memb = ultima.get("membresia") if ultima else None
    fh = _to_date(memb.get("fecha_hasta")) if isinstance(memb, dict) else None

    if not fh:
        nuevo_activo = False
    elif fh >= hoy:
        nuevo_activo = (not bloqueado)
    else:
        nuevo_activo = False

    clientes_col.update_one(
        {"_id": cliente_id},
        {"$set": {"activo": nuevo_activo, "estado_updated_at": datetime.utcnow()}}
    )

    return nuevo_activo





@web_bp.get("/cajero/config")
@login_required(role="cajero")
def cajero_config():
    return render_template("cajero_config.html")


@web_bp.post("/cajero/config/password")
@login_required(role="cajero")
def cajero_config_password():
    db = extensions.mongo_db
    users_col = db["users"]
    username = session.get("username")

    current = request.form.get("current_password", "")
    new1 = request.form.get("new_password", "")
    new2 = request.form.get("new_password2", "")

    if not new1 or new1 != new2:
        flash("La nueva contraseña no coincide.", "danger")
        return redirect(url_for("web.cajero_config"))

    user = users_col.find_one({"username": username})
    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("web.cajero_config"))

    # bcrypt
    if not extensions.bcrypt.check_password_hash(user.get("password_hash", ""), current):
        flash("Contraseña actual incorrecta.", "danger")
        return redirect(url_for("web.cajero_config"))

    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password_hash": extensions.bcrypt.generate_password_hash(new1).decode("utf-8"),
            "must_change_password": False
        }}
    )

    flash("Contraseña actualizada.", "success")
    return redirect(url_for("web.cajero_config"))

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
        "vendedor_username": session.get("username"),
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
        {"$set": {"activo": True, "bloqueado_manual": False, "estado_updated_at": datetime.utcnow()}}
        )


    flash(
        f"Suscripción renovada: {f_desde.strftime('%d/%m/%Y')} → {f_hasta.strftime('%d/%m/%Y')}",
        "success"
    )
    return redirect(url_for("web.cajero_dashboard"))

@web_bp.post("/cajero/clientes/<cliente_id>/estado")
@login_required(role="cajero")
def cajero_cliente_estado(cliente_id):
    db = extensions.mongo_db
    clientes_col = db["clientes"]

    try:
        oid = ObjectId(cliente_id)
    except Exception:
        flash("Cliente inválido.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    accion = (request.form.get("accion") or "").strip()  

    if accion == "bloquear":
        clientes_col.update_one({"_id": oid}, {"$set": {"bloqueado_manual": True}})
    elif accion == "desbloquear":
        clientes_col.update_one({"_id": oid}, {"$set": {"bloqueado_manual": False}})
    else:
        flash("Acción inválida.", "danger")
        return redirect(url_for("web.cajero_clientes"))

    sync_cliente_activo_por_membresia(db, oid)

    flash("Estado actualizado.", "success")
    return redirect(url_for("web.cajero_clientes"))



# Entrenador

@web_bp.get("/entrenador")
@login_required(role="entrenador")
def entrenador_dashboard():
    users = get_users_collection()
    entrenador = users.find_one({"username": session.get("username"), "role": "entrenador"})
    if not entrenador:
        flash("Entrenador no encontrado.", "danger")
        return redirect(url_for("web.logout"))

    ahora_local, clase_actual, proximas, clases_hoy, tz = obtener_clases_hoy_entrenador(entrenador["_id"])

    return render_template(
        "dashboard_entrenador.html",
        entrenador=entrenador,
        ahora_local=ahora_local,
        clase_actual=clase_actual,
        proximas=proximas,
        clases_hoy=clases_hoy,
        tz=tz,
        activate = "entrenador_dashboard"
    )


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


@web_bp.get("/cliente/dashboard")
@login_required(role="cliente")
def cliente_dashboard():
    db = extensions.mongo_db
    if db is None:
        return render_template(
            "dashboard_cliente.html",
            cliente=None,
            membresia=None,
            estado_membresia="Sin datos",
            dias_restantes=None,
            ultima_venta=None,
        )

    clientes_col = db["clientes"]
    ventas_col = db["ventas"]
    users_col = db["users"]

    user_id_raw = session.get("user_id")
    user_id = None

    if user_id_raw:
        try:
            user_id = ObjectId(str(user_id_raw))
        except Exception:
            user_id = None

    if not user_id:
        username = session.get("username")
        if username:
            u = users_col.find_one({"username": username}, {"_id": 1})
            if u:
                user_id = u["_id"]

    if not user_id:
        return render_template(
            "dashboard_cliente.html",
            cliente=None,
            membresia=None,
            estado_membresia="Sin datos",
            dias_restantes=None,
            ultima_venta=None,
        )

    cliente = clientes_col.find_one({"_id": user_id}) or {}

    ultima_venta = ventas_col.find_one(
        {"cliente_id": user_id},
        sort=[("fecha", -1)]
    )

    membresia = None
    estado_membresia = "Sin membresía"
    dias_restantes = None

    if ultima_venta and isinstance(ultima_venta.get("membresia"), dict):
        membresia = ultima_venta["membresia"]

        hoy = date.today()
        f_desde_date = _to_date(membresia.get("fecha_desde"))
        f_hasta_date = _to_date(membresia.get("fecha_hasta"))

        if f_hasta_date:
            if f_hasta_date >= hoy:
                estado_membresia = "Activa"
                dias_restantes = (f_hasta_date - hoy).days
            else:
                estado_membresia = "Vencida"
                dias_restantes = 0

        membresia["fecha_desde"] = f_desde_date
        membresia["fecha_hasta"] = f_hasta_date

    return render_template(
        "dashboard_cliente.html",
        cliente=cliente,
        membresia=membresia,
        estado_membresia=estado_membresia,
        dias_restantes=dias_restantes,
        ultima_venta=ultima_venta
    )






# Horarios Semanales

@web_bp.get("/horarios")
@login_required()
def horarios_publico():
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

    if view == "week":
        start = d - timedelta(days=d.weekday()) 
        week_dates = [start + timedelta(days=i) for i in range(7)]
        prev_date = start - timedelta(days=7)
        next_date = start + timedelta(days=7)

        slot_map = {}  
        all_slots = []

        for wd in week_dates:
            day_key = weekday_map[wd.weekday()]

            day_cfg = (cfg.get("dias") or {}).get(day_key, {"activo": False, "plantilla_id": None})

            bloques = resolver_bloques_del_dia(day_cfg)
            slots = construir_slots_para_fecha(wd, bloques, intervalo_minutos, cupo_maximo)

            slot_map[wd.isoformat()] = {s["inicio"].strftime("%H:%M"): s for s in slots}
            all_slots.extend(slots)

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
        )

    day_key = weekday_map[d.weekday()]
    day_cfg = (cfg.get("dias") or {}).get(day_key, {"activo": False, "plantilla_id": None})

    bloques = resolver_bloques_del_dia(day_cfg)
    slots = construir_slots_para_fecha(d, bloques, intervalo_minutos, cupo_maximo)

    return render_template(
        "horarios_publico.html",
        fecha=d,
        slots=slots,
        cfg=cfg,
        day_cfg=day_cfg
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

def _cajero_owns_cliente(db, cajero_username, cliente_id):
    ventas_col = db["ventas"]
    return ventas_col.find_one({"cliente_id": cliente_id, "vendedor_username": cajero_username}, {"_id": 1}) is not None


