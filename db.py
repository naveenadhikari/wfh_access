"""
db.py
-----
Sets up the sqlite database used by the admin panel.

Tables:
  - admins                    : admin login accounts (username, password_hash, otp_seed)
  - audit_log                 : record of who created which user, when, with what access
  - role_templates             : predefined access "roles" (Developer, Log Viewer, etc.)
  - wfh_users                  : WFH employee accounts (username, password, OTP, access flags)
  - wfh_user_region_overrides  : per-user, per-region custom access (replaces overRiddenRegionAndCfg)
  - global_settings            : rarely-changing global config (regionAndCfg, webAccessConfig, etc.)

Run this file directly to (re)create the database:
    python3 db.py
"""

import sqlite3
import json
import os

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

    conn.commit()
    conn.close()
    migrate_db()
    print("Tables created (or already existed) at:", DB_PATH)


def migrate_db():
    """Apply lightweight schema migrations for existing databases."""
    conn = get_db()
    cols = {row[1] for row in conn.execute("PRAGMA table_info(wfh_users)").fetchall()}
    if "ssh_public_key" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN ssh_public_key TEXT")
    if "ssh_key_updated_at" not in cols:
        conn.execute("ALTER TABLE wfh_users ADD COLUMN ssh_key_updated_at TEXT")
    conn.commit()
    conn.close()


def add_audit_entry(admin_username, target_user, action, details=None):
    """
    Insert one row into audit_log.
    `details` can be any JSON-serializable dict; we store it as a JSON string.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_log (admin_username, target_user, action, details) VALUES (?, ?, ?, ?)",
        (admin_username, target_user, action, json.dumps(details or {}))
    )
    conn.commit()
    conn.close()


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
                  allow_hp_agent_access, ports_to_open, region_overrides=None):
    """
    Insert a new WFH user (and optional per-region overrides).
    region_overrides: dict like { "ap-south-1": {"securityGrpIds": [...], "portsToOpen": [...]} }
    """
    conn = get_db()
    conn.execute("""
        INSERT INTO wfh_users
            (username, password_hash, otp_seed, allow_log_access, allow_metrics_access,
             allow_hp_agent_access, ports_to_open)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        username, password_hash, otp_seed,
        int(allow_log_access), int(allow_metrics_access), int(allow_hp_agent_access),
        json.dumps(ports_to_open)
    ))

    if region_overrides:
        for region, cfg in region_overrides.items():
            conn.execute("""
                INSERT INTO wfh_user_region_overrides (username, region, security_group_ids, ports_to_open)
                VALUES (?, ?, ?, ?)
            """, (username, region, json.dumps(cfg["securityGrpIds"]), json.dumps(cfg["portsToOpen"])))

    conn.commit()
    conn.close()
def update_wfh_user(username, allow_log_access, allow_metrics_access, allow_hp_agent_access, ports_to_open):
    """
    Update an existing WFH user's permissions.
    """
    conn = get_db()
    conn.execute("""
        UPDATE wfh_users
        SET allow_log_access = ?, allow_metrics_access = ?, allow_hp_agent_access = ?, ports_to_open = ?
        WHERE username = ?
    """, (
        int(allow_log_access), int(allow_metrics_access), int(allow_hp_agent_access),
        json.dumps(ports_to_open), username
    ))
    conn.commit()
    conn.close()


def delete_wfh_user(username):
    """Delete a WFH user and their region overrides."""
    conn = get_db()
    conn.execute("DELETE FROM wfh_user_region_overrides WHERE username = ?", (username,))
    conn.execute("DELETE FROM wfh_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_ssh_public_key(username):
    conn = get_db()
    row = conn.execute(
        "SELECT ssh_public_key, ssh_key_updated_at FROM wfh_users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "ssh_public_key": row["ssh_public_key"],
        "ssh_key_updated_at": row["ssh_key_updated_at"],
    }


def set_ssh_public_key(username, ssh_public_key):
    conn = get_db()
    conn.execute(
        """
        UPDATE wfh_users
        SET ssh_public_key = ?, ssh_key_updated_at = CURRENT_TIMESTAMP
        WHERE username = ?
        """,
        (ssh_public_key, username),
    )
    conn.commit()
    conn.close()


def get_all_ssh_key_status():
    """Return {username: {has_key, ssh_key_updated_at}} for every WFH user."""
    conn = get_db()
    rows = conn.execute(
        "SELECT username, ssh_public_key, ssh_key_updated_at FROM wfh_users"
    ).fetchall()
    conn.close()
    return {
        row["username"]: {
            "has_key": bool(row["ssh_public_key"]),
            "ssh_key_updated_at": row["ssh_key_updated_at"],
        }
        for row in rows
    }


if __name__ == "__main__":
    init_db()
    seed_role_templates()