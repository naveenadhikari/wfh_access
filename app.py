"""
Routes:
  GET      /                      - redirect to login or dashboard
  GET/POST /login                 - unified login (admin or employee)
  GET      /logout                - clear session
  GET      /admin/login           - redirect to /login
  GET      /employee/login        - redirect to /login
  GET      /admin/dashboard       - admin dashboard
  GET      /admin/users           - list all WFH users
  GET/POST /admin/add-user        - add a new WFH user
  GET/POST /admin/edit-user/<u>   - edit a user's permissions
  POST     /admin/delete-user/<u> - delete a user
  GET      /admin/audit-log       - view audit log
  GET/POST /employee/dashboard    - employee dashboard (SSH key; access granted at login)
  GET/POST /request-access        - redirects to /login (POST kept for compatibility)
  GET      /admin/user/<u>/ssh-key - admin view/copy user SSH key
  POST     /allow-access          - legacy curl endpoint
"""

import os
import io
import json
import base64
import secrets
import string
from functools import wraps

import datetime
import qrcode
import pyotp
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from auth import verify_admin, verify_wfh_user, hash_password, check_password, verify_otp_with_seed, generate_otp_seed
from db import (
    get_db, add_audit_entry, get_recent_audit_entries, get_user_ssh_keys, add_user_ssh_key,
    delete_user_ssh_key, get_all_ssh_key_status, migrate_db, get_all_admins, get_admin,
    update_admin_permissions, generate_admin_api_token, get_admin_by_api_token, delete_admin,
    get_global_setting, set_global_setting, get_wfh_user, get_employee_by_api_token, get_all_wfh_users,
    generate_employee_api_token, update_employee_permissions,
)
from config_writer import add_user_to_config, user_exists, list_users, get_access_cfg
from manage_wfh_access import grant_authorized_access
from ssh_keys import normalize_ssh_public_key
from permissions import (
    ALL_PERMISSIONS, PERMISSION_DEFINITIONS, permissions_from_form,
    has_any_permission, has_subadmin_access, parse_permissions,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
migrate_db()

import requests

SVRMETRICS_URL     = "http://localhost:6400"
SVRMETRICS_API_KEY = "svrmetrics-api-key-change-this"
import jwt
SSO_SECRET = "a1b2c34d5e6f7g8h9i0jklmnopqrstuvwx"  

@app.route("/launch/svrmetrics")
def launch_svrmetrics():
    username = session.get("employee_username") or session.get("admin_username")
    if not username:
        return redirect(url_for("login"))

    # Step 1 — whitelist their IP first
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        resp = requests.post(
            f"{SVRMETRICS_URL}/api/whitelist-ip",
            json={"ip": user_ip, "emp_name": username},
            headers={"X-API-Key": SVRMETRICS_API_KEY},
            timeout=5
        )
        if resp.status_code != 200:
            flash("Could not grant access to monitoring server.", "error")
            return redirect(url_for("dashboard"))
    except Exception:
        flash("Monitoring server is unreachable.", "error")
        return redirect(url_for("dashboard"))

    # Step 2 — generate token and redirect
    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
    }, SSO_SECRET, algorithm="HS256")

    return redirect(f"{SVRMETRICS_URL}/?token={token}")



#>>>>>>>
@app.context_processor
def inject_permission_helpers():
    return {
        "PERMISSION_DEFINITIONS": PERMISSION_DEFINITIONS,
        "session_permissions": _session_permissions(),
        "has_perm": lambda name: _has_permission(name),
        "is_employee_portal": lambda: bool(session.get("employee_username")),
    }


# Helpers
def _session_permissions():
    if session.get("admin_username"):
        if session.get("admin_role") == "superadmin":
            return ALL_PERMISSIONS
        return session.get("admin_permissions") or {}
    if session.get("employee_username"):
        return session.get("employee_permissions") or {}
    return {}


def _has_permission(name):
    return bool(_session_permissions().get(name))


def _current_actor():
    return session.get("admin_username") or session.get("employee_username")


def _home_url():
    if session.get("employee_username"):
        return url_for("employee_dashboard")
    return url_for("dashboard")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("admin_username"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped

def require_any_permission(*perm_names):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not _current_actor():
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if session.get("admin_role") == "superadmin":
                return view_func(*args, **kwargs)
            perms = _session_permissions()
            if any(perms.get(p) for p in perm_names):
                return view_func(*args, **kwargs)
            flash(f"You do not have permission ({' or '.join(perm_names)}).", "error")
            return redirect(_home_url())
        return wrapped
    return decorator


def employee_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("employee_username"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _grant_employee_access(username):
    ip_to_allow = _client_ip()
    access_result = grant_authorized_access(username, ip_to_allow)
    return (
        f"Access granted for {username} (IP {ip_to_allow}):\n"
        + json.dumps(access_result, indent=2)
    )


def _employee_dashboard_context(username, access_result=None):
    from config_writer import get_access_cfg
    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    db_user = get_wfh_user(username) or {}
    perms = db_user.get("admin_permissions") or {}
    ssh_keys = get_user_ssh_keys(username)
    return {
        "username": username,
        "ssh_keys": ssh_keys,
        "access_result": access_result,
        "user_info": user_info,
        "employee_permissions": perms,
        "has_subadmin_access": has_subadmin_access(perms),
        "api_token": db_user.get("api_token"),
    }


def _get_global_regions():
    """Region → security group map for admin user forms."""
    regions = get_access_cfg().get("regionAndCfg") or {}
    if not regions:
        from access_wfh_cfg import ACCESS_MANAGER_CONF
        regions = ACCESS_MANAGER_CONF.get("regionAndCfg", {})
    return regions


def _add_user_form_context(role_templates, role_templates_json):
    return {
        "role_templates": role_templates,
        "role_templates_json": role_templates_json,
        "global_regions": _get_global_regions(),
    }


def _edit_user_form_context(username, user):
    db_user = get_wfh_user(username) or {}
    perms = db_user.get("admin_permissions") or {}
    return {
        "username": username,
        "user": user,
        "global_regions": _get_global_regions(),
        "is_subadmin": any(perms.values()),
    }


def generate_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_qr_code_b64(seed, username, issuer="WFH-Access"):
    uri = pyotp.totp.TOTP(seed).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


# Unified login
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("admin_username"):
            return redirect(url_for("dashboard"))
        if session.get("employee_username"):
            return redirect(url_for("employee_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        employee_username = username.lower().replace(" ", "_")
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()

        if verify_admin(username, password, otp):
            session.pop("employee_username", None)
            session.pop("employee_permissions", None)
            session["admin_username"] = username

            admin_data = get_admin(username)
            if admin_data:
                session["admin_role"] = admin_data["role"]
                session["admin_permissions"] = admin_data["permissions"]
            else:
                session["admin_role"] = "superadmin"
                session["admin_permissions"] = {}

            # Add admin IP to svrmetrics whitelist
            admin_ip = request.headers.get(
                "X-Forwarded-For",
                request.remote_addr
            )

            try:
                requests.post(
                    f"{SVRMETRICS_URL}/api/whitelist-ip",
                    json={
                        "ip": admin_ip,
                        "emp_name": username
                    },
                    headers={
                        "X-API-Key": SVRMETRICS_API_KEY
                    },
                    timeout=5
                )
            except Exception:
                pass

            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        if verify_wfh_user(employee_username, password, otp):
            session.pop("admin_username", None)
            session.pop("admin_role", None)
            session.pop("admin_permissions", None)

            session["employee_username"] = employee_username

            db_user = get_wfh_user(employee_username) or {}
            session["employee_permissions"] = (
                db_user.get("admin_permissions") or {}
            )

            access_result = _grant_employee_access(employee_username)

            # Add employee IP to svrmetrics whitelist
            employee_ip = request.headers.get(
                "X-Forwarded-For",
                request.remote_addr
            )

            try:
                print(
                    f"DEBUG — calling svrmetrics with IP: {employee_ip}"
                )

                requests.post(
                    f"{SVRMETRICS_URL}/api/whitelist-ip",
                    json={
                        "ip": employee_ip,
                        "emp_name": employee_username
                    },
                    headers={
                        "X-API-Key": SVRMETRICS_API_KEY
                    },
                    timeout=5
                )
            except Exception:
                pass

            flash(
                "Logged in successfully. WFH access has been opened for your IP.",
                "success"
            )

            session["employee_access_result"] = access_result

            add_audit_entry(
                admin_username="SYSTEM",
                target_user=employee_username,
                action="login",
                details={
                    "message": "User logged in and granted access"
                },
                ip_address=_client_ip()
            )

            return redirect(url_for("employee_dashboard"))

        flash("Invalid username, password, or OTP.", "error")

    return render_template("login.html")


@app.route("/admin/login")
def admin_login_redirect():
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
     # ──  ──
    emp_name = session.get("employee_username") or session.get("admin_username")
    if emp_name:
        try:
            requests.post(
                f"{SVRMETRICS_URL}/api/remove-ip",
                json={"emp_name": emp_name},
                headers={"X-API-Key": SVRMETRICS_API_KEY},
                timeout=5
            )
        except Exception:
            pass
    # ── END OF ADDITION ──
    session.pop("admin_username", None)
    session.pop("admin_role", None)
    session.pop("admin_permissions", None)
    session.pop("employee_username", None)
    session.pop("employee_permissions", None)
    session.pop("employee_access_result", None)
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/admin/logout")
def admin_logout():
    return logout()


# Dashboard
@app.route("/admin/dashboard")
@login_required
def dashboard():
    admin_data = get_admin(session["admin_username"])
    api_token = admin_data.get("api_token") if admin_data else None
    return render_template("dashboard.html", api_token=api_token)



# View Users page
@app.route("/admin/users")
@require_any_permission("can_view_users_and_logs", "can_manage_users")
def view_users():
    users = list_users()
    ssh_key_status = get_all_ssh_key_status()
    return render_template("users.html", users=users, ssh_key_status=ssh_key_status)


# AWS Region Management

@app.route("/admin/regions")
@require_any_permission("can_manage_users")
def view_regions():
    regions = _get_global_regions()
    return render_template("regions.html", regions=regions)

@app.route("/admin/regions/add", methods=["POST"])
@require_any_permission("can_manage_users")
def add_region():
    region = request.form.get("region", "").strip()
    sgs_raw = request.form.get("sgs", "").strip()
    
    if not region:
        flash("Region name is required.", "error")
        return redirect(url_for("view_regions"))
        
    sgs = [sg.strip() for sg in sgs_raw.split(",") if sg.strip()]
    
    regions = _get_global_regions()
    if region in regions:
        flash(f"Region {region} already exists.", "error")
        return redirect(url_for("view_regions"))
        
    regions[region] = {"securityGrpIds": sgs}
    set_global_setting("regionAndCfg", regions)
    
    add_audit_entry(
        admin_username=_current_actor(),
        target_user="SYSTEM",
        action="add_region",
        details={"region": region, "securityGrpIds": sgs},
        ip_address=_client_ip()
    )
    
    flash(f"Region {region} added successfully.", "success")
    return redirect(url_for("view_regions"))

@app.route("/admin/regions/update", methods=["POST"])
@require_any_permission("can_manage_users")
def update_region():
    region = request.form.get("region", "").strip()
    sgs_raw = request.form.get("sgs", "").strip()
    
    if not region:
        flash("Region name is required.", "error")
        return redirect(url_for("view_regions"))
        
    sgs = [sg.strip() for sg in sgs_raw.split(",") if sg.strip()]
    
    regions = _get_global_regions()
    if region not in regions:
        flash(f"Region {region} not found.", "error")
        return redirect(url_for("view_regions"))
        
    regions[region]["securityGrpIds"] = sgs
    set_global_setting("regionAndCfg", regions)
    
    add_audit_entry(
        admin_username=_current_actor(),
        target_user="SYSTEM",
        action="update_region",
        details={"region": region, "securityGrpIds": sgs},
        ip_address=_client_ip()
    )
    
    flash(f"Region {region} updated successfully.", "success")
    return redirect(url_for("view_regions"))

@app.route("/admin/regions/delete/<region>", methods=["POST"])
@require_any_permission("can_manage_users")
def delete_region(region):
    regions = _get_global_regions()
    if region in regions:
        del regions[region]
        set_global_setting("regionAndCfg", regions)
        
        add_audit_entry(
            admin_username=_current_actor(),
            target_user="SYSTEM",
            action="delete_region",
            details={"region": region},
        ip_address=_client_ip()
    )
        flash(f"Region {region} deleted successfully.", "success")
    else:
        flash(f"Region {region} not found.", "error")
        
    return redirect(url_for("view_regions"))


# Add User

@app.route("/admin/add-user", methods=["GET", "POST"])
@require_any_permission("can_add_user", "can_manage_users")
def add_user():
    conn = get_db()
    role_templates = conn.execute("SELECT * FROM role_templates").fetchall()
    conn.close()

    role_templates_json = json.dumps({
        str(t["id"]): {
            "allow_log_access": t["allow_log_access"],
            "allow_metrics_access": t["allow_metrics_access"],
            "allow_hp_agent_access": t["allow_hp_agent_access"],
            "ports_to_open": json.loads(t["ports_to_open"]),
        }
        for t in role_templates
    })

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        """ Get the server2_username from the form """
        server2_username = request.form.get("server2_username", "").strip() or None
        allow_log = bool(request.form.get("allow_log_access"))
        allow_metrics = bool(request.form.get("allow_metrics_access"))
        allow_hp_agent = bool(request.form.get("allow_hp_agent_access"))
        ports_raw = request.form.get("ports_to_open", "").strip()

        if not username:
            flash("Username is required.", "error")
            return render_template(
                "add_user.html",
                **_add_user_form_context(role_templates, role_templates_json),
            )

        if user_exists(username):
            flash(f"User '{username}' already exists.", "error")
            return render_template(
                "add_user.html",
                **_add_user_form_context(role_templates, role_templates_json),
            )

        ports_to_open = []
        if ports_raw:
            try:
                ports_to_open = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except ValueError:
                flash("Ports must be numbers e.g. 22,3306", "error")
                return render_template(
                    "add_user.html",
                    **_add_user_form_context(role_templates, role_templates_json),
                )

        plain_password = generate_password()
        password_hash = hash_password(plain_password)

        otp_choice = request.form.get("otp_choice", "new")
        existing_seed = request.form.get("existing_otp_seed", "").strip()

        if otp_choice == "existing" and existing_seed:
            otp_seed = existing_seed
            is_new_seed = False
        else:
            otp_seed = generate_otp_seed()
            is_new_seed = True

        user_entry = {
            "password": password_hash,
            "otpSeed": otp_seed,
            "allowLogAccess": allow_log,
            "allowHpAgentAccess": allow_hp_agent,
            "allowServerMetricsAccess": allow_metrics,
        }
        if ports_to_open:
            user_entry["portsToOpen"] = ports_to_open

        # Parse region overrides
        override_regions = request.form.getlist("override_region[]")
        override_sgs_list = request.form.getlist("override_sgs[]")
        override_ports_list = request.form.getlist("override_ports[]")

        region_overrides = {}
        for i, region in enumerate(override_regions):
            region = region.strip()
            if not region:
                continue

            sgs_raw = override_sgs_list[i] if i < len(override_sgs_list) else ""
            ports_raw_over = override_ports_list[i] if i < len(override_ports_list) else ""

            sgs = [sg.strip() for sg in sgs_raw.split(",") if sg.strip()]
            try:
                ports = [int(p.strip()) for p in ports_raw_over.split(",") if p.strip()]
            except ValueError:
                flash(f"Ports for region '{region}' must be numbers.", "error")
                return render_template(
                    "add_user.html",
                    **_add_user_form_context(role_templates, role_templates_json),
                )

            region_overrides[region] = {
                "securityGrpIds": sgs,
                    "portsToOpen": ports
            }

        if region_overrides:
            user_entry["overRiddenRegionAndCfg"] = region_overrides

        if request.form.get("is_subadmin"):
            user_entry["adminPermissions"] = {"can_fetch_credentials": True}
        else:
            user_entry["adminPermissions"] = {}

        add_user_to_config(username, user_entry)

      

        add_audit_entry(
            admin_username=_current_actor(),
            target_user=username,
            action="create_user",
            details={
                "allowLogAccess": allow_log,
                "allowServerMetricsAccess": allow_metrics,
                "allowHpAgentAccess": allow_hp_agent,
                "portsToOpen": ports_to_open,
                "otpSeedSource": "new" if is_new_seed else "existing",
            }
        )

        qr_code_b64 = generate_qr_code_b64(otp_seed, username) if is_new_seed else None

        return render_template(
            "user_created.html",
            username=username,
            password=plain_password,
            otp_seed=otp_seed,
            is_new_seed=is_new_seed,
            qr_code_b64=qr_code_b64,
            access_summary={
                "allow_log_access": allow_log,
                "allow_metrics_access": allow_metrics,
                "allow_hp_agent_access": allow_hp_agent,
                "ports_to_open": ", ".join(str(p) for p in ports_to_open) if ports_to_open else None,
            }
        )

    return render_template(
        "add_user.html",
        **_add_user_form_context(role_templates, role_templates_json),
    )

# Edit User
@app.route("/admin/edit-user/<username>", methods=["GET", "POST"])
@require_any_permission("can_manage_users")
def edit_user(username):
    cfg = get_access_cfg()
    user = cfg["ALLOWED_USR_IDENTITIES"].get(username)

    if not user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("view_users"))

    if request.method == "POST":
        allow_log = bool(request.form.get("allow_log_access"))
        allow_metrics = bool(request.form.get("allow_metrics_access"))
        allow_hp_agent = bool(request.form.get("allow_hp_agent_access"))
        ports_raw = request.form.get("ports_to_open", "").strip()

        ports_to_open = []
        if ports_raw:
            try:
                ports_to_open = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except ValueError:
                flash("Ports must be numbers e.g. 22,3306", "error")
                return render_template(
                    "edit_user.html",
                    **_edit_user_form_context(username, user),
                )

        # Parse region overrides
        override_regions = request.form.getlist("override_region[]")
        override_sgs_list = request.form.getlist("override_sgs[]")
        override_ports_list = request.form.getlist("override_ports[]")

        region_overrides = {}
        for i, region in enumerate(override_regions):
            region = region.strip()
            if not region:
                continue

            sgs_raw = override_sgs_list[i] if i < len(override_sgs_list) else ""
            ports_raw_over = override_ports_list[i] if i < len(override_ports_list) else ""

            sgs = [sg.strip() for sg in sgs_raw.split(",") if sg.strip()]
            try:
                ports = [int(p.strip()) for p in ports_raw_over.split(",") if p.strip()]
            except ValueError:
                flash(f"Ports for region '{region}' must be numbers.", "error")
                return render_template(
                    "edit_user.html",
                    **_edit_user_form_context(username, user),
                )

            region_overrides[region] = {
                "securityGrpIds": sgs,
                "portsToOpen": ports
            }

        # Update via config writer (which updates db)
        user_entry = {
            "allowLogAccess": allow_log,
            "allowServerMetricsAccess": allow_metrics,
            "allowHpAgentAccess": allow_hp_agent,
            "portsToOpen": ports_to_open
        }
        user_entry["overRiddenRegionAndCfg"] = region_overrides

        db_user = get_wfh_user(username) or {}
        old_perms = db_user.get("admin_permissions") or {}
        
        if request.form.get("is_subadmin"):
            if old_perms and any(old_perms.values()):
                user_entry["adminPermissions"] = old_perms
            else:
                user_entry["adminPermissions"] = {"can_fetch_credentials": True}
        else:
            user_entry["adminPermissions"] = {}

        from config_writer import update_user_in_config
        update_user_in_config(username, user_entry)

        add_audit_entry(
            admin_username=_current_actor(),
            target_user=username,
            action="edit_user",
            details={
                "allowLogAccess": allow_log,
                "allowServerMetricsAccess": allow_metrics,
                "allowHpAgentAccess": allow_hp_agent,
                "portsToOpen": ports_to_open,
            }
        )

        flash(f"User '{username}' updated successfully.", "success")
        return redirect(url_for("view_users"))

    return render_template("edit_user.html", **_edit_user_form_context(username, user))


# Delete User
@app.route("/admin/delete-user/<username>", methods=["POST"])
@require_any_permission("can_manage_users")
def delete_user(username):
    if not user_exists(username):
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("view_users"))

    conn = get_db()
    conn.execute("DELETE FROM wfh_user_region_overrides WHERE username = ?", (username,))
    conn.execute("DELETE FROM wfh_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    add_audit_entry(
        admin_username=_current_actor(),
        target_user=username,
        action="delete_user",
        details={"message": "User deleted from database."},
        ip_address=_client_ip()
    )

    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("view_users"))


# Audit Log page

@app.route("/admin/audit-log/delete", methods=["POST"])
@require_any_permission("can_view_users_and_logs")
def delete_audit_log_data():
    days = request.form.get("days", type=int)
    if days and days > 0:
        from db import delete_old_audit_logs
        deleted = delete_old_audit_logs(days)
        add_audit_entry(
            admin_username=_current_actor(),
            target_user="SYSTEM",
            action="delete_logs",
            details={"message": f"Deleted {deleted} audit logs older than {days} days."},
            ip_address=_client_ip()
        )
        flash(f"Deleted {deleted} audit logs older than {days} days.", "success")
    return redirect(url_for("view_audit_log"))

@app.route("/admin/audit-log")
@require_any_permission("can_view_users_and_logs")
def view_audit_log():
    audit_entries = get_recent_audit_entries(limit=50)
    return render_template("audit_log.html", audit_entries=audit_entries)


@app.route("/admin/user/<username>/ssh-key")
@require_any_permission("can_view_users_and_logs", "can_manage_users", "can_fetch_credentials")
def view_user_ssh_key(username):
    if not user_exists(username):
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("view_users"))

    ssh_keys = get_user_ssh_keys(username)
    return render_template(
        "admin_ssh_key.html",
        username=username,
        ssh_keys=ssh_keys,
    )


# Subadmins Management
@app.route("/admin/admins", methods=["GET"])
@require_any_permission("can_manage_users", "can_view_users_and_logs")
def view_admins():
    all_users = get_all_wfh_users()
    subadmins = {u: data for u, data in all_users.items() if data.get("is_subadmin")}
    return render_template("admins.html", subadmins=subadmins, PERMISSION_DEFINITIONS=PERMISSION_DEFINITIONS)

@app.route("/admin/admins/<username>/update-subadmin", methods=["POST"])
@require_any_permission("can_manage_users")
def update_subadmin_route(username):
    perms = permissions_from_form(request.form)
    
    db_user = get_wfh_user(username)
    if not db_user:
        flash("User not found.", "error")
        return redirect(url_for("view_admins"))
        
    update_employee_permissions(username, perms)

    add_audit_entry(
        admin_username=_current_actor(),
        target_user=username,
        action="update_subadmin_privileges",
        details={"permissions": perms},
        ip_address=_client_ip()
    )
    flash(f"Subadmin privileges updated for {username}.", "success")
    return redirect(url_for("view_admins"))


# Employee portal
@app.route("/employee/login")
def employee_login_redirect():
    return redirect(url_for("login"))


@app.route("/employee/logout")
def employee_logout():
    return logout()


@app.route("/employee/dashboard", methods=["GET", "POST"])
@employee_login_required
def employee_dashboard():
    username = session["employee_username"]
    access_result = session.pop("employee_access_result", None)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add_key":
            key_name = request.form.get("key_name", "").strip() or f"Key {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
            raw_key = request.form.get("ssh_public_key", "")
            normalized_key = normalize_ssh_public_key(raw_key)

            if not normalized_key:
                flash("Invalid SSH public key. Paste a single-line key (ssh-rsa, ssh-ed25519, etc.).", "error")
                return render_template(
                    "employee_dashboard.html",
                    **_employee_dashboard_context(username, access_result=access_result),
                )

            add_user_ssh_key(username, key_name, normalized_key)
            add_audit_entry(
                admin_username=username,
                target_user=username,
                action="upload_ssh_key",
                details={"message": f"Employee uploaded SSH public key '{key_name}'."},
        ip_address=_client_ip()
    )
            flash("SSH public key saved successfully.", "success")
            return redirect(url_for("employee_dashboard"))

    return render_template("employee_dashboard.html", **_employee_dashboard_context(username, access_result=access_result))


@app.route("/employee/ssh-key/delete/<int:key_id>", methods=["POST"])
@employee_login_required
def delete_ssh_key(key_id):
    username = session["employee_username"]
    delete_user_ssh_key(username, key_id)
    add_audit_entry(
        admin_username=username,
        target_user=username,
        action="delete_ssh_key",
        details={"message": f"Employee deleted SSH key ID {key_id}."},
        ip_address=_client_ip()
    )
    flash("SSH public key deleted successfully.", "success")
    return redirect(url_for("employee_dashboard"))


@app.route("/employee/ssh-key/generate", methods=["POST"])
@employee_login_required
def generate_ssh_key():
    username = session["employee_username"]
    
    # Generate Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize private key
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    pub_key_str = pub_bytes.decode('utf-8')
    
    key_name = f"Generated Key {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    add_user_ssh_key(username, key_name, pub_key_str)
    add_audit_entry(
        admin_username=username,
        target_user=username,
        action="generate_ssh_key",
        details={"message": f"Employee generated a new SSH key pair '{key_name}'."},
        ip_address=_client_ip()
    )
    
    # Send private key as file download
    mem = io.BytesIO()
    mem.write(priv_bytes)
    mem.seek(0)
    
    return send_file(
        mem,
        as_attachment=True,
        download_name="id_ed25519",
        mimetype="application/x-pem-file"
    )


@app.route("/employee/api-token/generate", methods=["POST"])
@employee_login_required
def generate_employee_api_token_route():
    username = session["employee_username"]
    if not _has_permission("can_fetch_credentials"):
        flash("You do not have permission to generate an API token.", "error")
        return redirect(url_for("employee_dashboard"))
    generate_employee_api_token(username)
    flash("New API token generated.", "success")
    return redirect(url_for("employee_dashboard"))


# Script API for Credentials
@app.route("/api/v1/users/<username>/credentials", methods=["GET"])
def api_get_credentials(username):
    # Verify Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    admin = get_admin_by_api_token(token)
    employee = get_employee_by_api_token(token) if not admin else None
    
    if admin:
        if admin["role"] != "superadmin" and not admin["permissions"].get("can_fetch_credentials"):
            return jsonify({"error": "Forbidden. Missing can_fetch_credentials permission."}), 403
    elif employee:
        if not employee["admin_permissions"].get("can_fetch_credentials"):
            return jsonify({"error": "Forbidden. Missing can_fetch_credentials permission."}), 403
    else:
        return jsonify({"error": "Forbidden"}), 403

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    from config_writer import get_access_cfg
    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    
    ssh_keys = get_user_ssh_keys(username)
    
    response_data = {
        "username": username,
        "otp_seed": user_info.get("otpSeed"),
        "ssh_keys": [
            {
                "id": k["id"],
                "name": k["key_name"],
                "public_key": k["ssh_public_key"],
                "created_at": k["created_at"]
            }
            for k in ssh_keys
        ]
    }
    
    return jsonify(response_data)


# Legacy request-access URL (redirects to unified employee portal)
@app.route("/request-access", methods=["GET", "POST"])
def request_access():
    if request.method == "GET":
        if session.get("employee_username"):
            return redirect(url_for("employee_dashboard"))
        if session.get("admin_username"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    username = request.form.get("username", "").strip().lower().replace(" ", "_")
    password = request.form.get("password", "")
    otp = request.form.get("otp", "").strip()

    if verify_wfh_user(username, password, otp):
        session.pop("admin_username", None)
        session.pop("admin_role", None)
        session.pop("admin_permissions", None)
        session["employee_username"] = username
        db_user = get_wfh_user(username) or {}
        session["employee_permissions"] = db_user.get("admin_permissions") or {}
        access_result = _grant_employee_access(username)
        session["employee_access_result"] = access_result
        return redirect(url_for("employee_dashboard"))

    flash("Invalid username, password, or OTP.", "error")
    return redirect(url_for("login"))


# Legacy curl endpoint (backward compatibility)
@app.route("/allow-access", methods=["POST"])
def allow_access():
    import logging
    logger = logging.getLogger("")

    response = {"status": False}
    ip_to_allow = request.headers.get("X-Forwarded-For", request.remote_addr)

    try:
        req_body = request.json
        passw = req_body["password"]
        emp_name = req_body["name"]
        user_sent_otp = req_body.get("otp")
        emp_name = emp_name.lower().replace(" ", "_")
    except Exception as e:
        logger.exception("EXC: {}".format(e))
        return jsonify(response)

    cfg = get_access_cfg()
    error = "UnAuthorized.."
    status = False

    if emp_name in cfg["ALLOWED_USR_IDENTITIES"]:
        if cfg["ALLOWED_USR_IDENTITIES"][emp_name]["password"] == passw:
            if verify_otp_with_seed(user_sent_otp, cfg["ALLOWED_USR_IDENTITIES"][emp_name]["otpSeed"]):
                status = grant_authorized_access(emp_name, ip_to_allow)
                if status:
                    add_audit_entry(
                        admin_username="SYSTEM",
                        target_user=emp_name,
                        action="api_login",
                        details={"message": "User requested access via API/curl"},
                        ip_address=ip_to_allow
                    )
            else:
                logger.error("Invalid OTP")
        else:
            logger.error("Invalid Password")
    else:
        logger.error("NonExistent User")

    response["status"] = status
    if not status:
        response["error"] = error
    else:
        response["info"] = "Welcome {}".format(emp_name)

    return jsonify(response)


# Landing page

# (Removed index function as / is now handled by login)


if __name__ == "__main__":
    PORT = os.environ.get("ADMIN_PORT", 6300)
    app.run(host="0.0.0.0", port=int(PORT), debug=True)