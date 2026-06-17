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

import qrcode
import pyotp
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

from auth import verify_admin, verify_wfh_user, hash_password, check_password, verify_otp_with_seed, generate_otp_seed
from db import get_db, add_audit_entry, get_recent_audit_entries, get_ssh_public_key, set_ssh_public_key, get_all_ssh_key_status, migrate_db
from config_writer import add_user_to_config, user_exists, list_users, get_access_cfg
from manage_wfh_access import grant_authorized_access
from ssh_keys import normalize_ssh_public_key

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
migrate_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("admin_username"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


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
    ssh_info = get_ssh_public_key(username)
    return {
        "username": username,
        "ssh_public_key": ssh_info["ssh_public_key"] if ssh_info else None,
        "ssh_key_updated_at": ssh_info["ssh_key_updated_at"] if ssh_info else None,
        "access_result": access_result,
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


# ---------------------------------------------------------------------------
# Unified login
# ---------------------------------------------------------------------------
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
            session["admin_username"] = username
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        if verify_wfh_user(employee_username, password, otp):
            session.pop("admin_username", None)
            session["employee_username"] = employee_username
            access_result = _grant_employee_access(employee_username)
            flash("Logged in successfully. WFH access has been opened for your IP.", "success")
            return render_template(
                "employee_dashboard.html",
                **_employee_dashboard_context(employee_username, access_result=access_result),
            )

        flash("Invalid username, password, or OTP.", "error")

    return render_template("login.html")


@app.route("/admin/login")
def admin_login_redirect():
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("admin_username", None)
    session.pop("employee_username", None)
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/admin/logout")
def admin_logout():
    return logout()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/admin/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# View Users page
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@login_required
def view_users():
    users = list_users()
    ssh_key_status = get_all_ssh_key_status()
    return render_template("users.html", users=users, ssh_key_status=ssh_key_status)


# ---------------------------------------------------------------------------
# Add User
# ---------------------------------------------------------------------------
@app.route("/admin/add-user", methods=["GET", "POST"])
@login_required
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
            return render_template("add_user.html", role_templates=role_templates,
                                   role_templates_json=role_templates_json)

        if user_exists(username):
            flash(f"User '{username}' already exists.", "error")
            return render_template("add_user.html", role_templates=role_templates,
                                   role_templates_json=role_templates_json)

        ports_to_open = []
        if ports_raw:
            try:
                ports_to_open = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except ValueError:
                flash("Ports must be numbers e.g. 22,3306", "error")
                return render_template("add_user.html", role_templates=role_templates,
                                       role_templates_json=role_templates_json)

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

        add_user_to_config(username, user_entry)

        add_audit_entry(
            admin_username=session["admin_username"],
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

    return render_template("add_user.html", role_templates=role_templates,
                           role_templates_json=role_templates_json)


# ---------------------------------------------------------------------------
# Edit User
# ---------------------------------------------------------------------------
@app.route("/admin/edit-user/<username>", methods=["GET", "POST"])
@login_required
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
                return render_template("edit_user.html", username=username, user=user)

        conn = get_db()
        conn.execute("""
            UPDATE wfh_users SET
                allow_log_access = ?,
                allow_metrics_access = ?,
                allow_hp_agent_access = ?,
                ports_to_open = ?
            WHERE username = ?
        """, (
            int(allow_log), int(allow_metrics), int(allow_hp_agent),
            json.dumps(ports_to_open), username
        ))
        conn.commit()
        conn.close()

        add_audit_entry(
            admin_username=session["admin_username"],
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

    return render_template("edit_user.html", username=username, user=user)


# ---------------------------------------------------------------------------
# Delete User
# ---------------------------------------------------------------------------
@app.route("/admin/delete-user/<username>", methods=["POST"])
@login_required
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
        admin_username=session["admin_username"],
        target_user=username,
        action="delete_user",
        details={"message": "User deleted from database."}
    )

    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("view_users"))


# ---------------------------------------------------------------------------
# Audit Log page
# ---------------------------------------------------------------------------
@app.route("/admin/audit-log")
@login_required
def view_audit_log():
    audit_entries = get_recent_audit_entries(limit=50)
    return render_template("audit_log.html", audit_entries=audit_entries)


@app.route("/admin/user/<username>/ssh-key")
@login_required
def view_user_ssh_key(username):
    if not user_exists(username):
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for("view_users"))

    ssh_info = get_ssh_public_key(username)
    return render_template(
        "admin_ssh_key.html",
        username=username,
        ssh_public_key=ssh_info["ssh_public_key"] if ssh_info else None,
        ssh_key_updated_at=ssh_info["ssh_key_updated_at"] if ssh_info else None,
    )


# ---------------------------------------------------------------------------
# Employee portal
# ---------------------------------------------------------------------------
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

    if request.method == "POST":
        raw_key = request.form.get("ssh_public_key", "")
        normalized_key = normalize_ssh_public_key(raw_key)

        if not normalized_key:
            flash("Invalid SSH public key. Paste a single-line key (ssh-rsa, ssh-ed25519, etc.).", "error")
            return render_template(
                "employee_dashboard.html",
                **_employee_dashboard_context(username),
            )

        set_ssh_public_key(username, normalized_key)
        add_audit_entry(
            admin_username=username,
            target_user=username,
            action="upload_ssh_key",
            details={"message": "Employee uploaded or updated SSH public key."},
        )
        flash("SSH public key saved successfully.", "success")
        return redirect(url_for("employee_dashboard"))

    return render_template("employee_dashboard.html", **_employee_dashboard_context(username))


# ---------------------------------------------------------------------------
# Legacy request-access URL (redirects to unified employee portal)
# ---------------------------------------------------------------------------
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
        session["employee_username"] = username
        access_result = _grant_employee_access(username)
        return render_template(
            "employee_dashboard.html",
            **_employee_dashboard_context(username, access_result=access_result),
        )

    flash("Invalid username, password, or OTP.", "error")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Legacy curl endpoint (backward compatibility)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------
# (Removed index function as / is now handled by login)


if __name__ == "__main__":
    PORT = os.environ.get("ADMIN_PORT", 6300)
    app.run(host="0.0.0.0", port=int(PORT), debug=True)