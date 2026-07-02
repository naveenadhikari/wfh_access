"""
Tables:
  - admins                    : admin login accounts (username, password_hash, otp_seed)
  - audit_log                 : record of who created which user, when, with what access
  - role_templates             : predefined access "roles" (Developer, Log Viewer, etc.)
  - wfh_users                  : WFH employee accounts (username, password, OTP, access flags)
  - wfh_user_region_overrides  : per-user, per-region custom access (replaces overRiddenRegionAndCfg)
  - global_settings            : rarely-changing global config (regionAndCfg, webAccessConfig, etc.)

"""

import sqlite3
import json
import os
import secrets

from permissions import parse_permissions

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.db")


def get_db():
    """
    Returns a sqlite3 connection.
    row_factory = sqlite3.Row lets us access columns by name, e.g. row["username"].
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't already exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_seed TEXT NOT NULL,
            role TEXT DEFAULT 'superadmin',
            permissions TEXT DEFAULT '{}',
            api_token TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT NOT NULL,
            target_user TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS role_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            allow_log_access INTEGER DEFAULT 0,
            allow_metrics_access INTEGER DEFAULT 0,
            allow_hp_agent_access INTEGER DEFAULT 0,
            ports_to_open TEXT DEFAULT '[]',
            region_cfg TEXT DEFAULT 'null'
        )
    """)

    # --- WFH user data (replaces access_wfh_cfg.py's ALLOWED_USR_IDENTITIES) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wfh_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            otp_seed TEXT NOT NULL,
            allow_log_access INTEGER DEFAULT 0,
            allow_metrics_access INTEGER DEFAULT 0,
            allow_hp_agent_access INTEGER DEFAULT 0,
            ports_to_open TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --- Per-user, per-region access overrides (replaces overRiddenRegionAndCfg) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wfh_user_region_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            region TEXT NOT NULL,
            security_group_ids TEXT NOT NULL,
            ports_to_open TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES wfh_users(username),
            UNIQUE(username, region)
        )
    """)

    # --- Global, rarely-changing settings (regionAndCfg, webAccessConfig, etc.) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # --- Multiple SSH keys per user ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            key_name TEXT NOT NULL,
            ssh_public_key TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES wfh_users(username)
        )
    """)

    conn.commit()
    conn.close()
    migrate_db()
    print("Tables created (or already existed) at:", DB_PATH)


def migrate_db():
    """Apply lightweight schema migrations for existing databases."""
    conn = get_db()
    
    # Old columns migration (kept for legacy/safety)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(wfh_users)").fetchall()}
    if "ssh_public_key" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN ssh_public_key TEXT")
    if "ssh_key_updated_at" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN ssh_key_updated_at TEXT")
    if "admin_permissions" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN admin_permissions TEXT DEFAULT '{}'")
    if "api_token" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN api_token TEXT")
        
    audit_cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if "ip_address" not in audit_cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN ip_address TEXT")

    admin_cols = {row[1] for row in conn.execute("PRAGMA table_info(admins)").fetchall()}
    if "role" not in admin_cols:
        conn.execute("ALTER TABLE admins ADD COLUMN role TEXT DEFAULT 'superadmin'")
    if "permissions" not in admin_cols:
        conn.execute("ALTER TABLE admins ADD COLUMN permissions TEXT DEFAULT '{}'")
    if "api_token" not in admin_cols:
        conn.execute("ALTER TABLE admins ADD COLUMN api_token TEXT")
    
    # New table migration
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            key_name TEXT NOT NULL,
            ssh_public_key TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES wfh_users(username)
        )
    """)
    
    # Migrate old keys to new table
    users_with_keys = conn.execute(
        "SELECT username, ssh_public_key, ssh_key_updated_at FROM wfh_users WHERE ssh_public_key IS NOT NULL AND ssh_public_key != ''"
    ).fetchall()
    
    for row in users_with_keys:
        username = row["username"]
        pub_key = row["ssh_public_key"]
        created_at = row["ssh_key_updated_at"]
        
        # Check if it already exists in the new table
        existing = conn.execute(
            "SELECT 1 FROM user_ssh_keys WHERE username = ? AND ssh_public_key = ?",
            (username, pub_key)
        ).fetchone()
        
        if not existing:
            conn.execute(
                "INSERT INTO user_ssh_keys (username, key_name, ssh_public_key, created_at) VALUES (?, ?, ?, ?)",
                (username, "Legacy Key", pub_key, created_at or "CURRENT_TIMESTAMP")
            )
            
        # We don't drop the old column since SQLite alter table drop column is complex
    
    # Migrate legacy subadmin accounts from admins table to employee privileges
    _migrate_subadmins_to_employee_privileges(conn)

    conn.commit()
    conn.close()


def _migrate_subadmins_to_employee_privileges(conn):
    """Move subadmin role/permissions from admins into wfh_users.admin_permissions."""
    subadmins = conn.execute(
        "SELECT username, permissions, api_token FROM admins WHERE role = 'subadmin'"
    ).fetchall()
    for row in subadmins:
        username = row["username"]
        perms = parse_permissions(row["permissions"])
        if not wfh_user_exists_in_conn(conn, username):
            continue
        conn.execute(
            "UPDATE wfh_users SET admin_permissions = ? WHERE username = ?",
            (json.dumps(perms), username),
        )
        if row["api_token"]:
            conn.execute(
                "UPDATE wfh_users SET api_token = ? WHERE username = ? AND (api_token IS NULL OR api_token = '')",
                (row["api_token"], username),
            )
        conn.execute("DELETE FROM admins WHERE username = ?", (username,))


def wfh_user_exists_in_conn(conn, username):
    return conn.execute(
        "SELECT 1 FROM wfh_users WHERE username = ?", (username,)
    ).fetchone() is not None


def add_audit_entry(admin_username, target_user, action, details=None, ip_address=None):
    """
    Insert one row into audit_log.
    `details` can be any JSON-serializable dict; we store it as a JSON string.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (admin_username, target_user, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (admin_username, target_user, action, json.dumps(details or {}), ip_address)
    )
    conn.commit()
    conn.close()


def delete_old_audit_logs(days):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM audit_log WHERE timestamp < datetime('now', ?)", (f'-{days} days',))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted

def get_recent_audit_entries(limit=20):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_role_templates():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM role_templates")
    rows = cur.fetchall()
    conn.close()
    return rows


def seed_role_templates():
    """Insert default role templates if they don't already exist."""
    conn = get_db()
    cur = conn.cursor()

    templates = [
        # name, allow_log, allow_metrics, allow_hp_agent, ports_to_open, region_cfg
        ("Log Viewer", 1, 1, 0, json.dumps([]), json.dumps(None)),
        ("Developer", 1, 1, 1, json.dumps([22]), json.dumps(None)),
        ("Full Access", 1, 1, 1, json.dumps([22, 3306]), json.dumps(None)),
    ]

    for t in templates:
        cur.execute("SELECT id FROM role_templates WHERE name = ?", (t[0],))
        if cur.fetchone() is None:
            cur.execute("""
                INSERT INTO role_templates
                    (name, allow_log_access, allow_metrics_access, allow_hp_agent_access, ports_to_open, region_cfg)
                VALUES (?, ?, ?, ?, ?, ?)
            """, t)
            print(f"Seeded role template: {t[0]}")
        else:
            print(f"Role template already exists: {t[0]}")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Global settings (key-value store for regionAndCfg, webAccessConfig, etc.)
# ---------------------------------------------------------------------------
def get_global_setting(key, default=None):
    conn = get_db()
    row = conn.execute("SELECT value FROM global_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row is None:
        return default
    return json.loads(row["value"])


def set_global_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO global_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value))
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Admin Management (RBAC)
# ---------------------------------------------------------------------------
def get_all_admins():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, permissions, api_token, created_at FROM admins").fetchall()
    conn.close()
    
    admins = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else {}
        admins.append(d)
    return admins


def get_admin(username):
    conn = get_db()
    row = conn.execute("SELECT id, username, role, permissions, api_token, created_at FROM admins WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else {}
        return d
    return None


def get_admin_by_api_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute("SELECT id, username, role, permissions, api_token, created_at FROM admins WHERE api_token = ?", (token,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else {}
        return d
    return None


def update_admin_permissions(username, role, permissions):
    conn = get_db()
    conn.execute(
        "UPDATE admins SET role = ?, permissions = ? WHERE username = ?",
        (role, json.dumps(permissions), username)
    )
    conn.commit()
    conn.close()


def generate_admin_api_token(username):
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute("UPDATE admins SET api_token = ? WHERE username = ?", (token, username))
    conn.commit()
    conn.close()
    return token


def delete_admin(username):
    conn = get_db()
    conn.execute("DELETE FROM admins WHERE username = ?", (username,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# WFH users (the actual employees getting WFH access)
# ---------------------------------------------------------------------------
def get_wfh_user(username):
    """Return a dict for one WFH user (with region overrides), or None."""
    conn = get_db()
    row = conn.execute("SELECT * FROM wfh_users WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.close()
        return None

    overrides = conn.execute(
        "SELECT * FROM wfh_user_region_overrides WHERE username = ?", (username,)
    ).fetchall()
    conn.close()

    user = dict(row)
    user["ports_to_open"] = json.loads(user["ports_to_open"])
    raw_perms = parse_permissions(user.get("admin_permissions"))
    user["admin_permissions"] = raw_perms
    user["is_subadmin"] = any(raw_perms.values()) if raw_perms else False
    if overrides:
        user["region_overrides"] = {
            o["region"]: {
                "securityGrpIds": json.loads(o["security_group_ids"]),
                "portsToOpen": json.loads(o["ports_to_open"]),
            }
            for o in overrides
        }
    else:
        user["region_overrides"] = None

    return user


def get_all_wfh_users():
    """Return a dict { username: user_dict } for all WFH users."""
    conn = get_db()
    usernames = [r["username"] for r in conn.execute("SELECT username FROM wfh_users").fetchall()]
    conn.close()
    return {u: get_wfh_user(u) for u in usernames}


def wfh_user_exists(username):
    conn = get_db()
    row = conn.execute("SELECT 1 FROM wfh_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row is not None


def add_wfh_user(username, password_hash, otp_seed, allow_log_access, allow_metrics_access,
                  allow_hp_agent_access, ports_to_open, region_overrides=None,
                  admin_permissions=None):
    """
    Insert a new WFH user (and optional per-region overrides).
    region_overrides: dict like { "ap-south-1": {"securityGrpIds": [...], "portsToOpen": [...]} }
    """
    conn = get_db()
    perms_json = json.dumps(parse_permissions(admin_permissions or {}))
    conn.execute("""
        INSERT INTO wfh_users
            (username, password_hash, otp_seed, allow_log_access, allow_metrics_access,
             allow_hp_agent_access, ports_to_open, admin_permissions)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, password_hash, otp_seed,
        int(allow_log_access), int(allow_metrics_access), int(allow_hp_agent_access),
        json.dumps(ports_to_open), perms_json,
    ))

    if region_overrides:
        for region, cfg in region_overrides.items():
            conn.execute("""
                INSERT INTO wfh_user_region_overrides (username, region, security_group_ids, ports_to_open)
                VALUES (?, ?, ?, ?)
            """, (username, region, json.dumps(cfg["securityGrpIds"]), json.dumps(cfg["portsToOpen"])))

    conn.commit()
    conn.close()
def update_wfh_user(username, allow_log_access, allow_metrics_access, allow_hp_agent_access,
                    ports_to_open, region_overrides=None, admin_permissions=None):
    """
    Update an existing WFH user's permissions and region overrides.
    """
    conn = get_db()
    if admin_permissions is not None:
        perms_json = json.dumps(parse_permissions(admin_permissions))
        conn.execute("""
            UPDATE wfh_users
            SET allow_log_access = ?, allow_metrics_access = ?, allow_hp_agent_access = ?,
                ports_to_open = ?, admin_permissions = ?
            WHERE username = ?
        """, (
            int(allow_log_access), int(allow_metrics_access), int(allow_hp_agent_access),
            json.dumps(ports_to_open), perms_json, username,
        ))
    else:
        conn.execute("""
            UPDATE wfh_users
            SET allow_log_access = ?, allow_metrics_access = ?, allow_hp_agent_access = ?,
                ports_to_open = ?
            WHERE username = ?
        """, (
            int(allow_log_access), int(allow_metrics_access), int(allow_hp_agent_access),
            json.dumps(ports_to_open), username,
        ))

    if region_overrides is not None:
        # Clear existing overrides
        conn.execute("DELETE FROM wfh_user_region_overrides WHERE username = ?", (username,))
        # Insert new ones
        for region, cfg in region_overrides.items():
            conn.execute("""
                INSERT INTO wfh_user_region_overrides (username, region, security_group_ids, ports_to_open)
                VALUES (?, ?, ?, ?)
            """, (username, region, json.dumps(cfg["securityGrpIds"]), json.dumps(cfg["portsToOpen"])))

    conn.commit()
    conn.close()


def delete_wfh_user(username):
    """Delete a WFH user and their region overrides."""
    conn = get_db()
    conn.execute("DELETE FROM wfh_user_region_overrides WHERE username = ?", (username,))
    conn.execute("DELETE FROM wfh_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_user_ssh_keys(username):
    """Return a list of SSH keys for the given user."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, key_name, ssh_public_key, created_at FROM user_ssh_keys WHERE username = ? ORDER BY created_at DESC",
        (username,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_user_ssh_key(username, key_name, ssh_public_key):
    """Add a new SSH public key for a user."""
    conn = get_db()
    conn.execute(
        """
        INSERT INTO user_ssh_keys (username, key_name, ssh_public_key)
        VALUES (?, ?, ?)
        """,
        (username, key_name, ssh_public_key),
    )
    conn.commit()
    conn.close()


def delete_user_ssh_key(username, key_id):
    """Delete a specific SSH public key for a user."""
    conn = get_db()
    conn.execute(
        "DELETE FROM user_ssh_keys WHERE username = ? AND id = ?",
        (username, key_id),
    )
    conn.commit()
    conn.close()


def update_employee_permissions(username, permissions):
    conn = get_db()
    conn.execute(
        "UPDATE wfh_users SET admin_permissions = ? WHERE username = ?",
        (json.dumps(parse_permissions(permissions)), username),
    )
    conn.commit()
    conn.close()


def get_employee_by_api_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT username, admin_permissions, api_token FROM wfh_users WHERE api_token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    user = dict(row)
    user["admin_permissions"] = parse_permissions(user.get("admin_permissions"))
    return user


def generate_employee_api_token(username):
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute("UPDATE wfh_users SET api_token = ? WHERE username = ?", (token, username))
    conn.commit()
    conn.close()
    return token


def get_all_ssh_key_status():
    """Return {username: {has_key, key_count}} for every WFH user."""
    conn = get_db()
    users = conn.execute("SELECT username FROM wfh_users").fetchall()
    
    status = {}
    for user in users:
        username = user["username"]
        count_row = conn.execute(
            "SELECT COUNT(*) as count FROM user_ssh_keys WHERE username = ?",
            (username,)
        ).fetchone()
        count = count_row["count"]
        status[username] = {
            "has_key": count > 0,
            "key_count": count
        }
        
    conn.close()
    return status


def get_user_provisioned_instances(username):
    """Retrieve unique active EC2 instances a user has been provisioned on from audit log."""
    conn = get_db()
    rows = conn.execute(
        "SELECT action, details FROM audit_log WHERE target_user = ? AND action IN ('ec2_provision', 'ec2_revoke') ORDER BY id ASC",
        (username,)
    ).fetchall()
    conn.close()
    
    instances = {}
    for row in rows:
        if row["details"]:
            details = json.loads(row["details"])
            instance_id = details.get("instance_id")
            if not instance_id:
                continue
                
            if row["action"] == "ec2_provision" and details.get("success", False):
                instances[instance_id] = details
            elif row["action"] == "ec2_revoke" and details.get("success", False):
                instances.pop(instance_id, None)
                
    return list(instances.values())


def get_all_active_ec2_provisions():
    """Retrieve all active EC2 provisions across all users."""
    conn = get_db()
    rows = conn.execute(
        "SELECT target_user, action, details, timestamp FROM audit_log WHERE action IN ('ec2_provision', 'ec2_revoke') ORDER BY id ASC"
    ).fetchall()
    conn.close()
    
    # Structure: active_provisions[username][instance_id] = details
    active_provisions = {}
    
    for row in rows:
        target_user = row["target_user"]
        if not target_user:
            continue
            
        if row["details"]:
            details = json.loads(row["details"])
            instance_id = details.get("instance_id")
            if not instance_id:
                continue
                
            if target_user not in active_provisions:
                active_provisions[target_user] = {}
                
            if row["action"] == "ec2_provision" and details.get("success", False):
                # Add provision details + timestamp
                details["provisioned_at"] = row["timestamp"]
                details["username"] = target_user
                active_provisions[target_user][instance_id] = details
            elif row["action"] == "ec2_revoke" and details.get("success", False):
                active_provisions[target_user].pop(instance_id, None)
                
    # Flatten out into a single list
    flat_provisions = []
    for user_provisions in active_provisions.values():
        flat_provisions.extend(user_provisions.values())
        
    # Sort by timestamp descending
    flat_provisions.sort(key=lambda x: x.get("provisioned_at", ""), reverse=True)
    return flat_provisions

if __name__ == "__main__":
    init_db()
    seed_role_templates()