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
import threading

import datetime
import qrcode
import pyotp

import requests
import jwt


from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from ec2_helper import list_regions, list_instances_in_region
from ec2_provision import provision_user_on_instance, ALLOWED_LINUX_GROUPS


from auth import verify_admin, verify_wfh_user, hash_password, check_password, generate_otp_seed
from db import (
    get_db, add_audit_entry, get_recent_audit_entries, get_user_ssh_keys, add_user_ssh_key,
    delete_user_ssh_key, get_all_ssh_key_status, migrate_db, get_all_admins, get_admin,
    get_admin_by_api_token, get_global_setting, set_global_setting, get_wfh_user, 
    get_employee_by_api_token, get_all_wfh_users, generate_employee_api_token, 
    update_employee_permissions, get_all_active_ec2_provisions,
)
from config_writer import add_user_to_config, user_exists, list_users, get_access_cfg
from manage_wfh_access import grant_authorized_access
from ssh_keys import normalize_ssh_public_key
from permissions import (
    ALL_PERMISSIONS, PERMISSION_DEFINITIONS, permissions_from_form,
    has_any_permission, has_subadmin_access, parse_permissions,
)

def load_env_file():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    os.environ[key] = val

load_env_file()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
migrate_db()


SVRMETRICS_URL     = os.environ.get("SVRMETRICS_URL")
SVRMETRICS_API_KEY = os.environ.get("SVRMETRICS_API_KEY")

SSO_SECRET = os.environ.get("SSO_SECRET")  

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


@app.context_processor
def inject_permission_helpers():
    return {
        "PERMISSION_DEFINITIONS": PERMISSION_DEFINITIONS,
        "session_permissions": _session_permissions(),
        "has_perm": lambda name: _has_permission(name),
        "is_employee_portal": lambda: bool(session.get("employee_username")),
        "get_active_regions": lambda: list(_get_global_regions().keys()),
    }



def async_post(url, json_data=None, headers=None, timeout=5):
    def task():
        try:
            requests.post(url, json=json_data, headers=headers, timeout=timeout)
        except Exception:
            pass
    threading.Thread(target=task, daemon=True).start()

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
    def background_task():
        grant_authorized_access(username, ip_to_allow)
    
    threading.Thread(target=background_task, daemon=True).start()
    
    return f"Access is being provisioned in the background for {username} (IP {ip_to_allow}). This may take a few moments."


def _employee_dashboard_context(username, access_result=None):
    from config_writer import get_access_cfg
    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    db_user = get_wfh_user(username) or {}
    perms = db_user.get("admin_permissions") or {}
    ssh_keys = get_user_ssh_keys(username)
    from db import get_user_provisioned_instances
    provisioned_instances = get_user_provisioned_instances(username)
    
    otp_seed = user_info.get("otpSeed")
    qr_code_b64 = generate_qr_code_b64(otp_seed, username) if otp_seed else None
    
    return {
        "username": username,
        "ssh_keys": ssh_keys,
        "access_result": access_result,
        "user_info": user_info,
        "employee_permissions": perms,
        "has_subadmin_access": has_subadmin_access(perms),
        "api_token": db_user.get("api_token"),
        "provisioned_instances": provisioned_instances,
        "qr_code_b64": qr_code_b64,
    }


def _get_global_regions():
    """Region → security group map for admin user forms."""
    regions = get_access_cfg().get("regionAndCfg") or {}
    
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
                async_post(
                    f"{SVRMETRICS_URL}/api/whitelist-ip",
                    json_data={
                        "ip": admin_ip,
                        "emp_name": username
                    },
                    headers={
                        "X-API-Key": SVRMETRICS_API_KEY
                    }
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

                async_post(
                    f"{SVRMETRICS_URL}/api/whitelist-ip",
                    json_data={
                        "ip": employee_ip,
                        "emp_name": employee_username
                    },
                    headers={
                        "X-API-Key": SVRMETRICS_API_KEY
                    }
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
            async_post(
                f"{SVRMETRICS_URL}/api/remove-ip",
                json_data={"emp_name": emp_name},
                headers={"X-API-Key": SVRMETRICS_API_KEY}
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
    users = list_users().copy()
    try:
        all_admins = {adm["username"] for adm in get_all_admins()}
        for adm_user in all_admins:
            users.pop(adm_user, None)
    except Exception:
        pass
    users.pop("admin", None) # Hard backup check
    ssh_key_status = get_all_ssh_key_status()
    return render_template("users.html", users=users, ssh_key_status=ssh_key_status)


# AWS Region Management

@app.route("/admin/regions")
@require_any_permission("can_manage_users")
def view_regions():
    regions = _get_global_regions()
    users = list_users()
    
    # Filter out admins from the users list for provisioning
    try:
        all_admins = {adm["username"] for adm in get_all_admins()}
        for adm_user in all_admins:
            users.pop(adm_user, None)
    except Exception:
        pass
    users.pop("admin", None)
    
    active_provisions = get_all_active_ec2_provisions()
    return render_template("regions.html", regions=regions, users=users, active_provisions=active_provisions)

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
    if region not in regions:
        flash(f"Region {region} not found.", "error")
        return redirect(url_for("view_regions"))
        
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
    return redirect(url_for("view_regions"))


@app.route("/admin/revoke-ec2", methods=["POST"])
@require_any_permission("can_manage_users")
def revoke_ec2():
    username = request.form.get("username")
    instance_ip = request.form.get("instance_ip")      # stored IP — may be stale
    instance_id = request.form.get("instance_id")
    instance_name = request.form.get("instance_name")
    region = request.form.get("region", "").strip()

    if not username or not instance_id:
        flash("Missing user or instance for revocation.", "error")
        return redirect(url_for("view_regions"))

    # The stored instance_ip can go stale if the instance was stopped/started
    # since it was provisioned (public IPs change on restart unless the
    # instance has an Elastic IP). Re-fetch the current IP from AWS instead
    # of trusting what's saved in the DB.
    current_ip = instance_ip
    if region:
        try:
            from ec2_helper import list_instances_in_region
            live_instances = list_instances_in_region(region)
            match = next((i for i in live_instances if i.get("id") == instance_id), None)

            if match is None:
                flash(f"Instance {instance_name} ({instance_id}) no longer exists in {region}. "
                      f"It may have been terminated — you may need to clean up this record manually.", "error")
                return redirect(url_for("view_regions"))

            if match.get("state") != "running":
                flash(f"Instance {instance_name} is currently '{match.get('state')}', not running. "
                      f"Start it first, then revoke.", "error")
                return redirect(url_for("view_regions"))

            if match.get("public_ip"):
                current_ip = match["public_ip"]
        except Exception as e:
            # Fall back to the stored IP if the live lookup itself fails —
            # better to try the old value than to block the action entirely.
            print(f"[WARN] Could not refresh IP for {instance_id}: {e}")

    if not current_ip:
        flash(f"No reachable IP found for {instance_name}. Is the instance running?", "error")
        return redirect(url_for("view_regions"))

    try:
        from ec2_provision import revoke_user_on_instance
        
        actor = _current_actor()
        client_ip = _client_ip()
        
        def revoke_task():
            success, error_msg = revoke_user_on_instance(public_ip=current_ip, username=username)

            details = {
                "instance_id": instance_id,
                "instance_name": instance_name,
                "instance_ip": current_ip,
                "success": success,
            }
            if error_msg:
                details["error"] = error_msg

            add_audit_entry(
                admin_username=actor,
                target_user=username,
                action="ec2_revoke",
                details=details,
                ip_address=client_ip
            )
            
        threading.Thread(target=revoke_task, daemon=True).start()
        flash(f"Revocation initiated in the background for '{username}' on {instance_name} ({current_ip}). Check audit logs later for status.", "success")

    except Exception as e:
        flash(f"Revocation error: {str(e)}", "error")

    return redirect(url_for("view_regions"))


@app.route("/admin/update-groups", methods=["POST"])
@require_any_permission("can_manage_users")
def update_groups():
    """
    Edit an existing provision's Linux group membership (add/remove groups)
    without a full re-provision — no SSH key / OTP / sshd changes, just
    reconciles group membership on the target instance.
    """
    username      = request.form.get("username")
    instance_ip   = request.form.get("instance_ip")      # stored IP — may be stale
    instance_id   = request.form.get("instance_id")
    instance_name = request.form.get("instance_name")
    region        = request.form.get("region", "").strip()
    selected_groups = [g for g in request.form.getlist("linux_groups") if g in ALLOWED_LINUX_GROUPS]

    if not username or not instance_id:
        flash("Missing user or instance for group update.", "error")
        return redirect(url_for("view_regions"))

    # Same stale-IP problem as revoke — re-fetch the live IP before connecting.
    current_ip = instance_ip
    if region:
        try:
            from ec2_helper import list_instances_in_region
            live_instances = list_instances_in_region(region)
            match = next((i for i in live_instances if i.get("id") == instance_id), None)

            if match is None:
                flash(f"Instance {instance_name} ({instance_id}) no longer exists in {region}.", "error")
                return redirect(url_for("view_regions"))

            if match.get("state") != "running":
                flash(f"Instance {instance_name} is currently '{match.get('state')}', not running. "
                      f"Start it first, then edit groups.", "error")
                return redirect(url_for("view_regions"))

            if match.get("public_ip"):
                current_ip = match["public_ip"]
        except Exception as e:
            print(f"[WARN] Could not refresh IP for {instance_id}: {e}")

    if not current_ip:
        flash(f"No reachable IP found for {instance_name}. Is the instance running?", "error")
        return redirect(url_for("view_regions"))

    try:
        from ec2_provision import update_user_groups_on_instance
        
        actor = _current_actor()
        client_ip = _client_ip()
        
        def update_task():
            success, result = update_user_groups_on_instance(
                public_ip=current_ip,
                username=username,
                groups=selected_groups,
            )

            details = {
                "instance_id": instance_id,
                "instance_name": instance_name,
                "instance_ip": current_ip,
                "region": region,
                "linux_groups": selected_groups,
                "success": success,
            }
            if isinstance(result, dict):
                details["change_result"] = result
            else:
                details["error"] = result

            add_audit_entry(
                admin_username=actor,
                target_user=username,
                action="ec2_update_groups",
                details=details,
                ip_address=client_ip
            )
            
        threading.Thread(target=update_task, daemon=True).start()
        flash(f"Groups update initiated in the background for '{username}' on {instance_name}. Check audit logs later for status.", "success")

    except Exception as e:
        flash(f"Group update error: {str(e)}", "error")

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
        cidr_preference = request.form.get("cidr_preference", "/32")

        conn = get_db()
        conn.execute(
        "UPDATE wfh_users SET cidr_preference=? WHERE username=?",
            (cidr_preference, username)
                )
        conn.commit()
        conn.close()

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


# ── ROUTE 1 — List EC2 instances for a region ──
@app.route("/api/ec2-instances/<region>")
def api_ec2_instances(region):
    if not session.get("admin_username"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        from ec2_helper import list_instances_in_region
        instances = list_instances_in_region(region)
        return jsonify({"instances": instances})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── ROUTE 2 — Provision EC2 access for a user ──
@app.route("/admin/provision-ec2/<username>", methods=["POST"])
@require_any_permission("can_manage_users")
def provision_ec2(username):
    instance_id   = request.form.get("instance_id", "").strip()
    instance_ip   = request.form.get("instance_ip", "").strip()
    region        = request.form.get("region", "").strip()
    instance_name = request.form.get("instance_name", instance_id)
    selected_groups = [g for g in request.form.getlist("linux_groups") if g in ALLOWED_LINUX_GROUPS]

    if not instance_id or not instance_ip:
        flash("Please select an EC2 instance.", "error")
        return redirect(url_for("edit_user", username=username))

    # Get employee's SSH public key from DB
    ssh_keys = get_user_ssh_keys(username)
    if not ssh_keys:
        flash(
            f"No SSH key found for '{username}'. "
            "Employee must add their SSH public key first from their dashboard.",
            "error"
        )
        return redirect(url_for("edit_user", username=username))

    ssh_public_key = ssh_keys[0]["ssh_public_key"]

    # Get employee's OTP seed from DB
    db_user = get_wfh_user(username)
    if not db_user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("edit_user", username=username))

    otp_seed = db_user.get("otp_seed")
    if not otp_seed:
        flash(f"No OTP seed found for '{username}'.", "error")
        return redirect(url_for("edit_user", username=username))

    try:
        from ec2_provision import provision_user_on_instance
        import os

        result = provision_user_on_instance(
            public_ip=instance_ip,
            username=username,
            ssh_public_key=ssh_public_key,
            otp_seed=otp_seed,
            groups=selected_groups,
        )

        add_audit_entry(
            admin_username=_current_actor(),
            target_user=username,
            action="ec2_provision",
            details={
                "instance_id":   instance_id,
                "instance_name": instance_name,
                "instance_ip":   instance_ip,
                "region":        region,
                "linux_groups":  selected_groups,
                "success":       result["success"],
                "steps":         {k: v for k, v in result.items() if k != "error"},
                "error":         result.get("error"),
            },
            ip_address=_client_ip()
        )

        if result["success"]:
            flash(
                f"✅ '{username}' provisioned on {instance_name} ({instance_ip}) successfully. "
                "They can now SSH using their key + OTP.",
                "success"
            )
        else:
            flash(
                f"⚠️ Provisioning partially failed for '{username}' on {instance_name}. "
                f"Error: {result.get('error', 'See audit log for details.')}",
                "error"
            )

    except Exception as e:
        flash(f"Provisioning error: {str(e)}", "error")

    return redirect(url_for("edit_user", username=username))


@app.route("/admin/provision-ec2-global", methods=["POST"])
@require_any_permission("can_manage_users")
def provision_ec2_global():
    username      = request.form.get("username", "").strip()
    instance_id   = request.form.get("instance_id", "").strip()
    instance_ip   = request.form.get("instance_ip", "").strip()
    region        = request.form.get("region", "").strip()
    instance_name = request.form.get("instance_name", instance_id)

    selected_groups = [g for g in request.form.getlist("linux_groups") if g in ALLOWED_LINUX_GROUPS]

    if not username or not instance_id or not instance_ip:
        flash("Please select a user and an EC2 instance.", "error")
        return redirect(url_for("view_regions"))

    # Get employee's SSH public key from DB
    ssh_keys = get_user_ssh_keys(username)
    if not ssh_keys:
        flash(
            f"No SSH key found for '{username}'. "
            "Employee must add their SSH public key first from their dashboard.",
            "error"
        )
        return redirect(url_for("view_regions"))
    
    ssh_public_key = ssh_keys[0]["ssh_public_key"]

    db_user = get_wfh_user(username)
    if not db_user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("view_regions"))

    otp_seed = db_user.get("otp_seed")
    if not otp_seed:
        flash(f"No OTP seed found for '{username}'.", "error")
        return redirect(url_for("view_regions"))

    try:
        from ec2_provision import provision_user_on_instance
        import os

        result = provision_user_on_instance(
            public_ip=instance_ip,
            username=username,
            ssh_public_key=ssh_public_key,
            otp_seed=otp_seed,
            groups=selected_groups,
        )

        add_audit_entry(
            admin_username=_current_actor(),
            target_user=username,
            action="ec2_provision",
            details={
                "instance_id":   instance_id,
                "instance_name": instance_name,
                "instance_ip":   instance_ip,
                "region":        region,
                "linux_groups":  selected_groups,
                "success":       result["success"],
                "steps":         {k: v for k, v in result.items() if k != "error"},
                "error":         result.get("error"),
            },
            ip_address=_client_ip()
        )

        if result["success"]:
            flash(
                f"✅ '{username}' provisioned on {instance_name} ({instance_ip}) successfully. ",
                "success"
            )
        else:
            flash(
                f"⚠️ Provisioning partially failed for '{username}' on {instance_name}. "
                f"Error: {result.get('error', 'See audit log for details.')}",
                "error"
            )

    except Exception as e:
        flash(f"Provisioning error: {str(e)}", "error")

    return redirect(url_for("view_regions"))



# ── ROUTE 3 — List available AWS regions ──
@app.route("/api/ec2-regions")
def api_ec2_regions():
    if not session.get("admin_username"):
        return jsonify({"error": "Unauthorized"}), 401
    from ec2_helper import list_regions
    return jsonify({"regions": list_regions()})


# ── ROUTE 4 — Check if user has SSH key on file ──
@app.route("/api/user-ssh-key-status/<username>")
def api_user_ssh_key_status(username):

    print(f"DEBUG ssh-key-status: session={dict(session)}")
    if not session.get("admin_username"):
        return jsonify({"error": "Unauthorized"}), 401
    keys = get_user_ssh_keys(username)
    if keys:
        return jsonify({
            "has_key": True,
            "key_name": keys[0]["key_name"],
            "created_at": keys[0]["created_at"],
            "key_count": len(keys)
        })
    return jsonify({"has_key": False})





# Landing page



if __name__ == "__main__":
    PORT = os.environ.get("ADMIN_PORT", 6300)
    app.run(host="0.0.0.0", port=int(PORT), debug=True)