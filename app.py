"""
WFH Access Portal — token-authenticated JSON API.

Authentication no longer uses Flask cookie sessions. Clients authenticate once
(POST /api/auth/login or via SAML SSO) and receive an opaque token. That token
must be sent in the `X-AUTH-TOKEN` header on every subsequent API request. The
browser UI is a separate single-page app served from /static/app (mounted at /).

API surface (all JSON unless noted):
  Auth
    POST   /api/auth/login          - username/password/OTP -> {token, ...}
    POST   /api/auth/logout         - revoke current token
    GET    /api/auth/me             - current identity + metadata
  SAML (browser navigation, not JSON)
    GET    /saml/login              - redirect to IdP
    POST   /saml/acs                - assertion -> issue token, redirect to SPA
    GET    /saml/metadata           - SP metadata XML
  Admin
    GET    /api/admin/users
    GET    /api/admin/add-user      - form context
    POST   /api/admin/add-user
    GET    /api/admin/users/<u>     - edit context
    PUT    /api/admin/users/<u>
    DELETE /api/admin/users/<u>
    GET    /api/admin/audit-log
    POST   /api/admin/audit-log/delete
    GET    /api/admin/users/<u>/ssh-key
    GET    /api/admin/admins
    POST   /api/admin/admins/<u>/permissions
    GET    /api/admin/regions
    POST   /api/admin/regions
    PUT    /api/admin/regions/<region>
    DELETE /api/admin/regions/<region>
    POST   /api/admin/regions/revoke-ec2
    POST   /api/admin/regions/update-groups
    POST   /api/admin/provision-ec2/<u>
    POST   /api/admin/provision-ec2-global
    GET    /api/ec2-regions
    GET    /api/ec2-instances/<region>
    GET    /api/user-ssh-key-status/<u>
  Employee
    GET    /api/employee/dashboard
    POST   /api/employee/ssh-keys
    DELETE /api/employee/ssh-keys/<id>
    POST   /api/employee/ssh-keys/generate   (binary download)
    POST   /api/employee/api-token
  Misc
    GET    /api/launch/svrmetrics   - returns {url} for the monitoring SSO jump
    GET    /api/v1/users/<u>/credentials  - long-lived Bearer API token (scripts)
"""

import os
import io
import json
import base64
import secrets
import string
import threading
from urllib.parse import quote

import datetime
import qrcode
import pyotp

import requests
import jwt


from flask import (
    Flask, request, redirect, jsonify, send_file, send_from_directory,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from saml_helper import get_saml_config, prepare_flask_request

from ec2_helper import list_regions, list_instances_in_region
from ec2_provision import ALLOWED_LINUX_GROUPS


from auth import verify_admin, verify_wfh_user, hash_password, generate_otp_seed
from db import (
    get_db, add_audit_entry, get_user_ssh_keys, add_user_ssh_key,
    delete_user_ssh_key, get_all_ssh_key_status, migrate_db, get_all_admins, get_admin,
    get_admin_by_api_token, set_global_setting, get_wfh_user,
    get_employee_by_api_token, get_all_wfh_users, generate_employee_api_token,
    update_employee_permissions, get_all_active_ec2_provisions,
    create_auth_session, delete_auth_session, delete_sessions_for_user,
    delete_expired_auth_sessions,
)
from config_writer import add_user_to_config, user_exists, list_users, get_access_cfg
from manage_wfh_access import grant_authorized_access
from ssh_keys import normalize_ssh_public_key
from permissions import (
    ALL_PERMISSIONS, PERMISSION_DEFINITIONS, has_subadmin_access, parse_permissions,
)
from token_auth import (
    current_identity, effective_permissions, is_admin_actor,
    token_required, admin_required, employee_required, require_permission,
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

# The SPA lives under static/app; static_url_path stays at the Flask default (/static).
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
migrate_db()
delete_expired_auth_sessions()

SPA_DIR = os.path.join(app.static_folder, "app")

SVRMETRICS_URL     = os.environ.get("SVRMETRICS_URL")
SVRMETRICS_API_KEY = os.environ.get("SVRMETRICS_API_KEY")

SSO_SECRET = os.environ.get("SSO_SECRET")

# Where the SAML flow should drop the browser back after issuing a token.
# Defaults to the SPA root; the token/error is appended in the URL fragment.
FRONTEND_URL = os.environ.get("FRONTEND_URL", "/")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def async_post(url, json_data=None, headers=None, timeout=5):
    def task():
        try:
            requests.post(url, json=json_data, headers=headers, timeout=timeout)
        except Exception:
            pass
    threading.Thread(target=task, daemon=True).start()


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _current_actor():
    ident = current_identity()
    return ident["username"] if ident else None


def _session_permissions():
    return effective_permissions(current_identity())


def _has_permission(name):
    return bool(_session_permissions().get(name))


def _get_global_regions():
    """Region -> security group map for admin user forms."""
    return get_access_cfg().get("regionAndCfg") or {}


def generate_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_qr_code_b64(seed, username, issuer="WFH-Access"):
    uri = pyotp.totp.TOTP(seed).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _whitelist_ip_async(ip, emp_name):
    if not SVRMETRICS_URL:
        return
    try:
        async_post(
            f"{SVRMETRICS_URL}/api/whitelist-ip",
            json_data={"ip": ip, "emp_name": emp_name},
            headers={"X-API-Key": SVRMETRICS_API_KEY},
        )
    except Exception:
        pass


def _grant_employee_access(username):
    ip_to_allow = _client_ip()

    def background_task():
        grant_authorized_access(username, ip_to_allow)

    threading.Thread(target=background_task, daemon=True).start()
    return (
        f"Access is being provisioned in the background for {username} "
        f"(IP {ip_to_allow}). This may take a few moments."
    )


def _permission_definitions_payload():
    return [{"key": key, "label": label} for key, label in PERMISSION_DEFINITIONS]


def _serialize_audit_entry(row):
    d = dict(row)
    if d.get("details"):
        try:
            d["details"] = json.loads(d["details"])
        except (TypeError, json.JSONDecodeError):
            d["details"] = {}
    else:
        d["details"] = {}
    return d


def _employee_dashboard_payload(username, access_result=None):
    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    db_user = get_wfh_user(username) or {}
    perms = db_user.get("admin_permissions") or {}
    ssh_keys = get_user_ssh_keys(username)
    from db import get_user_provisioned_instances
    provisioned_instances = get_user_provisioned_instances(username)

    return {
        "username": username,
        "ssh_keys": ssh_keys,
        "access_result": access_result,
        "user_info": {
            "allowLogAccess": user_info.get("allowLogAccess", False),
            "allowServerMetricsAccess": user_info.get("allowServerMetricsAccess", False),
            "allowHpAgentAccess": user_info.get("allowHpAgentAccess", False),
            "portsToOpen": user_info.get("portsToOpen", []),
        },
        "employee_permissions": perms,
        "has_subadmin_access": has_subadmin_access(perms),
        "api_token": db_user.get("api_token"),
        "provisioned_instances": provisioned_instances,
    }


# ---------------------------------------------------------------------------
# SPA hosting (static frontend served from same origin -> no CORS needed)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(SPA_DIR, "index.html")


@app.route("/app.js")
def spa_js():
    return send_from_directory(SPA_DIR, "app.js")


@app.route("/style.css")
def spa_css():
    return send_from_directory(SPA_DIR, "style.css")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    employee_username = username.lower().replace(" ", "_")
    password = data.get("password") or ""
    otp = (data.get("otp") or "").strip()

    if verify_admin(username, password, otp):
        # There is a single admin tier and it always holds every privilege.
        token = create_auth_session("admin", username, role="admin",
                                    permissions=ALL_PERMISSIONS)
        _whitelist_ip_async(_client_ip(), username)

        return jsonify({
            "token": token,
            "actor_type": "admin",
            "username": username,
            "role": "admin",
            "permissions": ALL_PERMISSIONS,
            "redirect": "dashboard",
        })

    if verify_wfh_user(employee_username, password, otp):
        db_user = get_wfh_user(employee_username) or {}
        permissions = db_user.get("admin_permissions") or {}
        token = create_auth_session("employee", employee_username, permissions=permissions)

        access_result = _grant_employee_access(employee_username)
        _whitelist_ip_async(_client_ip(), employee_username)

        add_audit_entry(
            admin_username="SYSTEM",
            target_user=employee_username,
            action="login",
            details={"message": "User logged in and granted access"},
            ip_address=_client_ip(),
        )

        return jsonify({
            "token": token,
            "actor_type": "employee",
            "username": employee_username,
            "role": "subadmin" if any(permissions.values()) else "user",
            "permissions": permissions,
            "access_message": access_result,
            "redirect": "employee",
        })

    return jsonify({"error": "Invalid username, password, or OTP."}), 401


@app.route("/api/auth/logout", methods=["POST"])
@token_required
def api_logout():
    ident = current_identity()
    emp_name = ident["username"]
    if SVRMETRICS_URL:
        try:
            async_post(
                f"{SVRMETRICS_URL}/api/remove-ip",
                json_data={"emp_name": emp_name},
                headers={"X-API-Key": SVRMETRICS_API_KEY},
            )
        except Exception:
            pass
    delete_auth_session(ident["token"])
    return jsonify({"ok": True})


@app.route("/api/auth/me", methods=["GET"])
@token_required
def api_me():
    ident = current_identity()
    perms = effective_permissions(ident)
    if is_admin_actor(ident):
        role = "admin"
    else:
        role = "subadmin" if any((ident.get("permissions") or {}).values()) else "user"
    return jsonify({
        "actor_type": ident["actor_type"],
        "username": ident["username"],
        "role": role,
        "permissions": perms,
        "permission_definitions": _permission_definitions_payload(),
        "active_regions": list(_get_global_regions().keys()),
    })


# ---------------------------------------------------------------------------
# SAML SSO
# ---------------------------------------------------------------------------
def _saml_redirect(fragment):
    # Fragment carries the token/error; the SPA reads it on load.
    base = FRONTEND_URL if FRONTEND_URL.endswith("/") else FRONTEND_URL + "/"
    return redirect(f"{base}#{fragment}")


@app.route("/saml/login")
def saml_login():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, get_saml_config(request))
    return redirect(auth.login())


@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, get_saml_config(request))
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        return _saml_redirect("saml_error=" + quote(", ".join(errors)))

    if not auth.is_authenticated():
        return _saml_redirect("saml_error=" + quote("Not authenticated."))

    email = auth.get_nameid()
    if not email:
        return _saml_redirect("saml_error=" + quote("No email provided by IdP."))

    username = email.split("@")[0].lower().replace(".", "_").replace(" ", "_")
    db_user = get_wfh_user(username)
    if not db_user:
        return _saml_redirect(
            "saml_error=" + quote(
                f"No account provisioned for '{username}'. Contact an administrator."
            )
        )

    permissions = db_user.get("admin_permissions") or {}
    token = create_auth_session("employee", username, permissions=permissions)

    _grant_employee_access(username)
    employee_ip = _client_ip()
    _whitelist_ip_async(employee_ip, username)

    add_audit_entry(
        admin_username="SYSTEM",
        target_user=username,
        action="sso_login",
        details={"message": "User logged in via SAML SSO and granted access"},
        ip_address=employee_ip,
    )

    # Hand the freshly minted token back to the SPA via the URL fragment.
    return _saml_redirect(f"saml_token={token}")


@app.route("/saml/metadata")
def saml_metadata():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, get_saml_config(request))
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) == 0:
        resp = app.make_response(metadata)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
    return ", ".join(errors), 500


# ---------------------------------------------------------------------------
# Monitoring SSO jump
# ---------------------------------------------------------------------------
@app.route("/api/launch/svrmetrics")
@token_required
def launch_svrmetrics():
    username = _current_actor()

    user_ip = _client_ip()
    try:
        resp = requests.post(
            f"{SVRMETRICS_URL}/api/whitelist-ip",
            json={"ip": user_ip, "emp_name": username},
            headers={"X-API-Key": SVRMETRICS_API_KEY},
            timeout=5,
        )
        if resp.status_code != 200:
            return jsonify({"error": "Could not grant access to monitoring server."}), 502
    except Exception:
        return jsonify({"error": "Monitoring server is unreachable."}), 502

    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
    }, SSO_SECRET, algorithm="HS256")

    return jsonify({"url": f"{SVRMETRICS_URL}/?token={token}"})


# ---------------------------------------------------------------------------
# Admin: users
# ---------------------------------------------------------------------------
@app.route("/api/admin/users")
@require_permission("can_view_users_and_logs", "can_manage_users")
def view_users():
    users = list_users().copy()
    try:
        all_admins = {adm["username"] for adm in get_all_admins()}
        for adm_user in all_admins:
            users.pop(adm_user, None)
    except Exception:
        pass
    users.pop("admin", None)
    ssh_key_status = get_all_ssh_key_status()
    # Include the actual SSH public keys so the user table can offer per-key copy
    # (OTP seed is already present on each user entry as `otpSeed`).
    ssh_keys = {
        u: [
            {"name": k["key_name"], "public_key": k["ssh_public_key"], "created_at": k["created_at"]}
            for k in get_user_ssh_keys(u)
        ]
        for u in users
    }
    return jsonify({"users": users, "ssh_key_status": ssh_key_status, "ssh_keys": ssh_keys})


@app.route("/api/admin/add-user", methods=["GET"])
@require_permission("can_add_user", "can_manage_users")
def add_user_form():
    conn = get_db()
    role_templates = conn.execute("SELECT * FROM role_templates").fetchall()
    conn.close()

    templates = [
        {
            "id": t["id"],
            "name": t["name"],
            "allow_log_access": t["allow_log_access"],
            "allow_metrics_access": t["allow_metrics_access"],
            "allow_hp_agent_access": t["allow_hp_agent_access"],
            "ports_to_open": json.loads(t["ports_to_open"]),
        }
        for t in role_templates
    ]
    return jsonify({
        "role_templates": templates,
        "global_regions": _get_global_regions(),
    })


def _parse_region_overrides(payload):
    """
    Accept region overrides as a list of
    {region, securityGrpIds:[...], portsToOpen:[...]} objects. Returns
    (overrides_dict, error_message_or_None).
    """
    overrides = {}
    for item in payload or []:
        region = (item.get("region") or "").strip()
        if not region:
            continue
        sgs = [s.strip() for s in (item.get("securityGrpIds") or []) if str(s).strip()]
        try:
            ports = [int(p) for p in (item.get("portsToOpen") or []) if str(p).strip()]
        except (ValueError, TypeError):
            return None, f"Ports for region '{region}' must be numbers."
        overrides[region] = {"securityGrpIds": sgs, "portsToOpen": ports}
    return overrides, None


@app.route("/api/admin/add-user", methods=["POST"])
@require_permission("can_add_user", "can_manage_users")
def add_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()

    allow_log = bool(data.get("allow_log_access"))
    allow_metrics = bool(data.get("allow_metrics_access"))
    allow_hp_agent = bool(data.get("allow_hp_agent_access"))

    if not username:
        return jsonify({"error": "Username is required."}), 400
    if user_exists(username):
        return jsonify({"error": f"User '{username}' already exists."}), 409

    ports_to_open = []
    try:
        ports_to_open = [int(p) for p in (data.get("ports_to_open") or []) if str(p).strip()]
    except (ValueError, TypeError):
        return jsonify({"error": "Ports must be numbers e.g. 22,3306"}), 400

    plain_password = generate_password()
    password_hash = hash_password(plain_password)

    otp_choice = data.get("otp_choice", "new")
    existing_seed = (data.get("existing_otp_seed") or "").strip()
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

    region_overrides, err = _parse_region_overrides(data.get("region_overrides"))
    if err:
        return jsonify({"error": err}), 400
    if region_overrides:
        user_entry["overRiddenRegionAndCfg"] = region_overrides

    if data.get("is_subadmin"):
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
        },
        ip_address=_client_ip(),
    )

    qr_code_b64 = generate_qr_code_b64(otp_seed, username) if is_new_seed else None

    return jsonify({
        "username": username,
        "password": plain_password,
        "otp_seed": otp_seed,
        "is_new_seed": is_new_seed,
        "qr_code_b64": qr_code_b64,
        "access_summary": {
            "allow_log_access": allow_log,
            "allow_metrics_access": allow_metrics,
            "allow_hp_agent_access": allow_hp_agent,
            "ports_to_open": ", ".join(str(p) for p in ports_to_open) if ports_to_open else None,
        },
    }), 201


@app.route("/api/admin/users/<username>", methods=["GET"])
@require_permission("can_manage_users")
def edit_user_form(username):
    cfg = get_access_cfg()
    user = cfg["ALLOWED_USR_IDENTITIES"].get(username)
    if not user:
        return jsonify({"error": f"User '{username}' not found."}), 404

    db_user = get_wfh_user(username) or {}
    perms = db_user.get("admin_permissions") or {}
    from db import get_user_provisioned_instances
    return jsonify({
        "username": username,
        "user": user,
        "cidr_preference": db_user.get("cidr_preference", "/32"),
        "global_regions": _get_global_regions(),
        "is_subadmin": any(perms.values()),
        "active_provisions": get_user_provisioned_instances(username),
    })


@app.route("/api/admin/users/<username>", methods=["PUT"])
@require_permission("can_manage_users")
def edit_user(username):
    cfg = get_access_cfg()
    user = cfg["ALLOWED_USR_IDENTITIES"].get(username)
    if not user:
        return jsonify({"error": f"User '{username}' not found."}), 404

    data = request.get_json(silent=True) or {}
    allow_log = bool(data.get("allow_log_access"))
    allow_metrics = bool(data.get("allow_metrics_access"))
    allow_hp_agent = bool(data.get("allow_hp_agent_access"))

    try:
        ports_to_open = [int(p) for p in (data.get("ports_to_open") or []) if str(p).strip()]
    except (ValueError, TypeError):
        return jsonify({"error": "Ports must be numbers e.g. 22,3306"}), 400

    region_overrides, err = _parse_region_overrides(data.get("region_overrides"))
    if err:
        return jsonify({"error": err}), 400

    cidr_preference = data.get("cidr_preference", "/32")
    conn = get_db()
    conn.execute(
        "UPDATE wfh_users SET cidr_preference=? WHERE username=?",
        (cidr_preference, username),
    )
    conn.commit()
    conn.close()

    user_entry = {
        "allowLogAccess": allow_log,
        "allowServerMetricsAccess": allow_metrics,
        "allowHpAgentAccess": allow_hp_agent,
        "portsToOpen": ports_to_open,
        "overRiddenRegionAndCfg": region_overrides,
    }

    db_user = get_wfh_user(username) or {}
    old_perms = db_user.get("admin_permissions") or {}
    if data.get("is_subadmin"):
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
        },
        ip_address=_client_ip(),
    )

    return jsonify({"ok": True, "message": f"User '{username}' updated successfully."})


@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_permission("can_manage_users")
def delete_user(username):
    if not user_exists(username):
        return jsonify({"error": f"User '{username}' not found."}), 404

    conn = get_db()
    conn.execute("DELETE FROM wfh_user_region_overrides WHERE username = ?", (username,))
    conn.execute("DELETE FROM wfh_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    # Revoke any active tokens for the deleted employee.
    delete_sessions_for_user("employee", username)

    add_audit_entry(
        admin_username=_current_actor(),
        target_user=username,
        action="delete_user",
        details={"message": "User deleted from database."},
        ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": f"User '{username}' deleted."})


@app.route("/api/admin/users/<username>/ssh-key")
@require_permission("can_view_users_and_logs", "can_manage_users", "can_fetch_credentials")
def view_user_ssh_key(username):
    if not user_exists(username):
        return jsonify({"error": f"User '{username}' not found."}), 404
    otp_seed = get_access_cfg()["ALLOWED_USR_IDENTITIES"].get(username, {}).get("otpSeed")
    return jsonify({
        "username": username,
        "otp_seed": otp_seed,
        "ssh_keys": get_user_ssh_keys(username),
    })


# ---------------------------------------------------------------------------
# Admin: audit log
# ---------------------------------------------------------------------------
@app.route("/api/admin/audit-log")
@require_permission("can_view_users_and_logs")
def view_audit_log():
    from db import get_audit_entries_page
    category = request.args.get("category", "actions")
    if category not in ("login", "actions"):
        category = "actions"
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = min(100, max(1, int(request.args.get("per_page", 15))))
    except (TypeError, ValueError):
        per_page = 15

    entries, total = get_audit_entries_page(category, page, per_page)
    pages = max(1, (total + per_page - 1) // per_page)
    return jsonify({
        "entries": [_serialize_audit_entry(e) for e in entries],
        "category": category,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
    })


@app.route("/api/admin/audit-log/delete", methods=["POST"])
@require_permission("can_view_users_and_logs")
def delete_audit_log_data():
    data = request.get_json(silent=True) or {}
    try:
        days = int(data.get("days"))
    except (TypeError, ValueError):
        days = 0
    if days and days > 0:
        from db import delete_old_audit_logs
        deleted = delete_old_audit_logs(days)
        add_audit_entry(
            admin_username=_current_actor(),
            target_user="SYSTEM",
            action="delete_logs",
            details={"message": f"Deleted {deleted} audit logs older than {days} days."},
            ip_address=_client_ip(),
        )
        return jsonify({"ok": True, "deleted": deleted,
                        "message": f"Deleted {deleted} audit logs older than {days} days."})
    return jsonify({"error": "days must be a positive integer."}), 400


# ---------------------------------------------------------------------------
# Admin: subadmins
# ---------------------------------------------------------------------------
@app.route("/api/admin/admins", methods=["GET"])
@require_permission("can_manage_users", "can_view_users_and_logs")
def view_admins():
    all_users = get_all_wfh_users()
    subadmins = {u: data for u, data in all_users.items() if data.get("is_subadmin")}
    return jsonify({
        "subadmins": subadmins,
        "permission_definitions": _permission_definitions_payload(),
    })


@app.route("/api/admin/admins/<username>/permissions", methods=["POST"])
@require_permission("can_manage_users")
def update_subadmin_route(username):
    data = request.get_json(silent=True) or {}
    raw_perms = data.get("permissions") or {}
    perms = parse_permissions(raw_perms)

    db_user = get_wfh_user(username)
    if not db_user:
        return jsonify({"error": "User not found."}), 404

    update_employee_permissions(username, perms)
    # No session revocation needed: permissions are resolved live per request
    # (see token_auth._load_identity), so the change applies on the subadmin's
    # next request without logging them out.

    add_audit_entry(
        admin_username=_current_actor(),
        target_user=username,
        action="update_subadmin_privileges",
        details={"permissions": perms},
        ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": f"Subadmin privileges updated for {username}."})


# ---------------------------------------------------------------------------
# Admin: regions + EC2
# ---------------------------------------------------------------------------
@app.route("/api/admin/regions")
@require_permission("can_manage_users", "can_manage_aws")
def view_regions():
    regions = _get_global_regions()
    users = list_users()
    try:
        all_admins = {adm["username"] for adm in get_all_admins()}
        for adm_user in all_admins:
            users.pop(adm_user, None)
    except Exception:
        pass
    users.pop("admin", None)

    active_provisions = get_all_active_ec2_provisions()
    return jsonify({
        "regions": regions,
        "users": users,
        "active_provisions": active_provisions,
        "allowed_linux_groups": sorted(ALLOWED_LINUX_GROUPS),
        # Adding/deleting regions from the catalog is a can_manage_users action.
        # can_manage_aws grants edit + EC2 provisioning only (no add/delete).
        "can_configure_regions": _has_permission("can_manage_users"),
    })


@app.route("/api/admin/regions", methods=["POST"])
@require_permission("can_manage_users")
def add_region():
    data = request.get_json(silent=True) or {}
    region = (data.get("region") or "").strip()
    sgs = [s.strip() for s in (data.get("securityGrpIds") or []) if str(s).strip()]

    if not region:
        return jsonify({"error": "Region name is required."}), 400

    regions = _get_global_regions()
    if region in regions:
        return jsonify({"error": f"Region {region} already exists."}), 409

    regions[region] = {"securityGrpIds": sgs}
    set_global_setting("regionAndCfg", regions)
    add_audit_entry(
        admin_username=_current_actor(), target_user="SYSTEM", action="add_region",
        details={"region": region, "securityGrpIds": sgs}, ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": f"Region {region} added successfully.", "regions": regions}), 201


@app.route("/api/admin/regions/<region>", methods=["PUT"])
@require_permission("can_manage_users", "can_manage_aws")
def update_region(region):
    data = request.get_json(silent=True) or {}
    sgs = [s.strip() for s in (data.get("securityGrpIds") or []) if str(s).strip()]

    regions = _get_global_regions()
    if region not in regions:
        return jsonify({"error": f"Region {region} not found."}), 404

    regions[region]["securityGrpIds"] = sgs
    set_global_setting("regionAndCfg", regions)
    add_audit_entry(
        admin_username=_current_actor(), target_user="SYSTEM", action="update_region",
        details={"region": region, "securityGrpIds": sgs}, ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": f"Region {region} updated successfully.", "regions": regions})


@app.route("/api/admin/regions/<region>", methods=["DELETE"])
@require_permission("can_manage_users")
def delete_region(region):
    regions = _get_global_regions()
    if region not in regions:
        return jsonify({"error": f"Region {region} not found."}), 404

    del regions[region]
    set_global_setting("regionAndCfg", regions)
    add_audit_entry(
        admin_username=_current_actor(), target_user="SYSTEM", action="delete_region",
        details={"region": region}, ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": f"Region {region} deleted successfully.", "regions": regions})


def _resolve_live_ip(region, instance_id, instance_name, stored_ip):
    """
    Re-fetch an instance's current public IP (public IPs change on stop/start).
    Returns (current_ip, error_message). error_message is a user-facing string
    when the operation should be aborted, else None.
    """
    current_ip = stored_ip
    if not region:
        return current_ip, None
    try:
        live_instances = list_instances_in_region(region)
        match = next((i for i in live_instances if i.get("id") == instance_id), None)
        if match is None:
            return None, (
                f"Instance {instance_name} ({instance_id}) no longer exists in {region}. "
                f"It may have been terminated."
            )
        if match.get("state") != "running":
            return None, (
                f"Instance {instance_name} is currently '{match.get('state')}', not running. "
                f"Start it first, then retry."
            )
        if match.get("public_ip"):
            current_ip = match["public_ip"]
    except Exception as e:
        print(f"[WARN] Could not refresh IP for {instance_id}: {e}")
    return current_ip, None


@app.route("/api/admin/regions/revoke-ec2", methods=["POST"])
@require_permission("can_manage_users", "can_manage_aws")
def revoke_ec2():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    instance_ip = data.get("instance_ip")
    instance_id = data.get("instance_id")
    instance_name = data.get("instance_name")
    region = (data.get("region") or "").strip()

    if not username or not instance_id:
        return jsonify({"error": "Missing user or instance for revocation."}), 400

    current_ip, err = _resolve_live_ip(region, instance_id, instance_name, instance_ip)
    if err:
        return jsonify({"error": err}), 409
    if not current_ip:
        return jsonify({"error": f"No reachable IP found for {instance_name}. Is the instance running?"}), 409

    from ec2_provision import revoke_user_on_instance
    actor = _current_actor()
    client_ip = _client_ip()

    def revoke_task():
        success, error_msg = revoke_user_on_instance(public_ip=current_ip, username=username)
        details = {
            "instance_id": instance_id, "instance_name": instance_name,
            "instance_ip": current_ip, "success": success,
        }
        if error_msg:
            details["error"] = error_msg
        add_audit_entry(admin_username=actor, target_user=username, action="ec2_revoke",
                        details=details, ip_address=client_ip)

    threading.Thread(target=revoke_task, daemon=True).start()
    return jsonify({"ok": True, "message": (
        f"Revocation initiated in the background for '{username}' on {instance_name} "
        f"({current_ip}). Check audit logs later for status."
    )})


@app.route("/api/admin/regions/update-groups", methods=["POST"])
@require_permission("can_manage_users", "can_manage_aws")
def update_groups():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    instance_ip = data.get("instance_ip")
    instance_id = data.get("instance_id")
    instance_name = data.get("instance_name")
    region = (data.get("region") or "").strip()
    selected_groups = [g for g in (data.get("linux_groups") or []) if g in ALLOWED_LINUX_GROUPS]

    if not username or not instance_id:
        return jsonify({"error": "Missing user or instance for group update."}), 400

    current_ip, err = _resolve_live_ip(region, instance_id, instance_name, instance_ip)
    if err:
        return jsonify({"error": err}), 409
    if not current_ip:
        return jsonify({"error": f"No reachable IP found for {instance_name}. Is the instance running?"}), 409

    from ec2_provision import update_user_groups_on_instance
    actor = _current_actor()
    client_ip = _client_ip()

    def update_task():
        success, result = update_user_groups_on_instance(
            public_ip=current_ip, username=username, groups=selected_groups,
        )
        details = {
            "instance_id": instance_id, "instance_name": instance_name,
            "instance_ip": current_ip, "region": region,
            "linux_groups": selected_groups, "success": success,
        }
        if isinstance(result, dict):
            details["change_result"] = result
        else:
            details["error"] = result
        add_audit_entry(admin_username=actor, target_user=username, action="ec2_update_groups",
                        details=details, ip_address=client_ip)

    threading.Thread(target=update_task, daemon=True).start()
    return jsonify({"ok": True, "message": (
        f"Groups update initiated in the background for '{username}' on {instance_name}. "
        f"Check audit logs later for status."
    )})


def _do_provision(username, instance_id, instance_ip, region, instance_name, selected_groups):
    """Shared provisioning logic. Returns (payload, status_code)."""
    if not username or not instance_id or not instance_ip:
        return {"error": "Please select a user and an EC2 instance."}, 400

    if instance_ip.upper() == "N/A":
        return {"error": (
            f"Instance '{instance_name}' has no public IP — it is likely stopped. "
            f"Start the instance so it gets a public IP, then provision again."
        )}, 400

    ssh_keys = get_user_ssh_keys(username)
    if not ssh_keys:
        return {"error": (
            f"No SSH key found for '{username}'. Employee must add their SSH public "
            f"key first from their dashboard."
        )}, 400
    ssh_public_key = ssh_keys[0]["ssh_public_key"]

    db_user = get_wfh_user(username)
    if not db_user:
        return {"error": f"User '{username}' not found."}, 404

    otp_seed = db_user.get("otp_seed")
    if not otp_seed:
        return {"error": f"No OTP seed found for '{username}'."}, 400

    from ec2_provision import provision_user_on_instance
    result = provision_user_on_instance(
        public_ip=instance_ip, username=username, ssh_public_key=ssh_public_key,
        otp_seed=otp_seed, groups=selected_groups,
    )
    add_audit_entry(
        admin_username=_current_actor(), target_user=username, action="ec2_provision",
        details={
            "instance_id": instance_id, "instance_name": instance_name,
            "instance_ip": instance_ip, "region": region,
            "linux_groups": selected_groups, "success": result["success"],
            "steps": {k: v for k, v in result.items() if k != "error"},
            "error": result.get("error"),
        },
        ip_address=_client_ip(),
    )
    if result["success"]:
        return {"ok": True, "message": (
            f"'{username}' provisioned on {instance_name} ({instance_ip}) successfully."
        )}, 200
    return {"ok": False, "error": (
        f"Provisioning partially failed for '{username}' on {instance_name}. "
        f"Error: {result.get('error', 'See audit log for details.')}"
    )}, 502


@app.route("/api/admin/provision-ec2/<username>", methods=["POST"])
@require_permission("can_manage_users", "can_manage_aws")
def provision_ec2(username):
    data = request.get_json(silent=True) or {}
    instance_id = (data.get("instance_id") or "").strip()
    instance_ip = (data.get("instance_ip") or "").strip()
    region = (data.get("region") or "").strip()
    instance_name = data.get("instance_name") or instance_id
    selected_groups = [g for g in (data.get("linux_groups") or []) if g in ALLOWED_LINUX_GROUPS]

    try:
        payload, status = _do_provision(username, instance_id, instance_ip, region,
                                         instance_name, selected_groups)
    except Exception as e:
        return jsonify({"error": f"Provisioning error: {str(e)}"}), 500
    return jsonify(payload), status


@app.route("/api/admin/provision-ec2-global", methods=["POST"])
@require_permission("can_manage_users", "can_manage_aws")
def provision_ec2_global():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    instance_id = (data.get("instance_id") or "").strip()
    instance_ip = (data.get("instance_ip") or "").strip()
    region = (data.get("region") or "").strip()
    instance_name = data.get("instance_name") or instance_id
    selected_groups = [g for g in (data.get("linux_groups") or []) if g in ALLOWED_LINUX_GROUPS]

    try:
        payload, status = _do_provision(username, instance_id, instance_ip, region,
                                         instance_name, selected_groups)
    except Exception as e:
        return jsonify({"error": f"Provisioning error: {str(e)}"}), 500
    return jsonify(payload), status


@app.route("/api/ec2-instances/<region>")
@require_permission("can_manage_users", "can_manage_aws")
def api_ec2_instances(region):
    try:
        instances = list_instances_in_region(region)
        return jsonify({"instances": instances})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ec2-regions")
@require_permission("can_manage_users", "can_manage_aws")
def api_ec2_regions():
    return jsonify({"regions": list_regions()})


@app.route("/api/user-ssh-key-status/<username>")
@admin_required
def api_user_ssh_key_status(username):
    keys = get_user_ssh_keys(username)
    if keys:
        return jsonify({
            "has_key": True,
            "key_name": keys[0]["key_name"],
            "created_at": keys[0]["created_at"],
            "key_count": len(keys),
        })
    return jsonify({"has_key": False})


# ---------------------------------------------------------------------------
# Employee portal
# ---------------------------------------------------------------------------
@app.route("/api/employee/dashboard", methods=["GET"])
@employee_required
def employee_dashboard():
    username = _current_actor()
    return jsonify(_employee_dashboard_payload(username))


@app.route("/api/employee/ssh-keys", methods=["POST"])
@employee_required
def add_employee_ssh_key():
    username = _current_actor()
    data = request.get_json(silent=True) or {}
    key_name = (data.get("key_name") or "").strip() or \
        f"Key {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    raw_key = data.get("ssh_public_key", "")
    normalized_key = normalize_ssh_public_key(raw_key)

    if not normalized_key:
        return jsonify({"error": (
            "Invalid SSH public key. Paste a single-line key "
            "(ssh-rsa, ssh-ed25519, etc.)."
        )}), 400

    add_user_ssh_key(username, key_name, normalized_key)
    add_audit_entry(
        admin_username=username, target_user=username, action="upload_ssh_key",
        details={"message": f"Employee uploaded SSH public key '{key_name}'."},
        ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": "SSH public key saved successfully."}), 201


@app.route("/api/employee/ssh-keys/<int:key_id>", methods=["DELETE"])
@employee_required
def delete_ssh_key(key_id):
    username = _current_actor()
    delete_user_ssh_key(username, key_id)
    add_audit_entry(
        admin_username=username, target_user=username, action="delete_ssh_key",
        details={"message": f"Employee deleted SSH key ID {key_id}."},
        ip_address=_client_ip(),
    )
    return jsonify({"ok": True, "message": "SSH public key deleted successfully."})


@app.route("/api/employee/ssh-keys/generate", methods=["POST"])
@employee_required
def generate_ssh_key():
    username = _current_actor()

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pub_key_str = pub_bytes.decode("utf-8")
    key_name = f"Generated Key {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"

    add_user_ssh_key(username, key_name, pub_key_str)
    add_audit_entry(
        admin_username=username, target_user=username, action="generate_ssh_key",
        details={"message": f"Employee generated a new SSH key pair '{key_name}'."},
        ip_address=_client_ip(),
    )

    mem = io.BytesIO()
    mem.write(priv_bytes)
    mem.seek(0)
    return send_file(
        mem, as_attachment=True, download_name="id_ed25519",
        mimetype="application/x-pem-file",
    )


@app.route("/api/employee/api-token", methods=["POST"])
@employee_required
def generate_employee_api_token_route():
    username = _current_actor()
    if not _has_permission("can_fetch_credentials"):
        return jsonify({"error": "You do not have permission to generate an API token."}), 403
    token = generate_employee_api_token(username)
    return jsonify({"ok": True, "api_token": token, "message": "New API token generated."})


# ---------------------------------------------------------------------------
# Script API for credentials (long-lived Bearer token, separate from sessions)
# ---------------------------------------------------------------------------
@app.route("/api/v1/users/<username>/credentials", methods=["GET"])
def api_get_credentials(username):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    admin = get_admin_by_api_token(token)
    employee = get_employee_by_api_token(token) if not admin else None

    if admin:
        pass  # admins hold every privilege
    elif employee:
        if not employee["admin_permissions"].get("can_fetch_credentials"):
            return jsonify({"error": "Forbidden. Missing can_fetch_credentials permission."}), 403
    else:
        return jsonify({"error": "Forbidden"}), 403

    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    ssh_keys = get_user_ssh_keys(username)

    return jsonify({
        "username": username,
        "otp_seed": user_info.get("otpSeed"),
        "ssh_keys": [
            {
                "id": k["id"], "name": k["key_name"],
                "public_key": k["ssh_public_key"], "created_at": k["created_at"],
            }
            for k in ssh_keys
        ],
    })


# Session-token credential lookup (used by the SPA "Fetch Credentials" panel).
# Gated on can_fetch_credentials, so both admins and permissioned subadmins can
# retrieve any user's OTP seed + SSH public keys via the X-AUTH-TOKEN header.
@app.route("/api/credentials/<username>", methods=["GET"])
@require_permission("can_fetch_credentials")
def api_lookup_credentials(username):
    if not user_exists(username):
        return jsonify({"error": "User not found"}), 404

    cfg = get_access_cfg()
    user_info = cfg["ALLOWED_USR_IDENTITIES"].get(username, {})
    otp_seed = user_info.get("otpSeed")
    ssh_keys = get_user_ssh_keys(username)

    add_audit_entry(
        admin_username=_current_actor(), target_user=username, action="fetch_credentials",
        details={"message": "Credentials fetched via dashboard."}, ip_address=_client_ip(),
    )

    return jsonify({
        "username": username,
        "otp_seed": otp_seed,
        "ssh_keys": [
            {
                "id": k["id"], "name": k["key_name"],
                "public_key": k["ssh_public_key"], "created_at": k["created_at"],
            }
            for k in ssh_keys
        ],
    })


if __name__ == "__main__":
    PORT = os.environ.get("ADMIN_PORT", 6300)
    app.run(host="0.0.0.0", port=int(PORT), debug=True)
