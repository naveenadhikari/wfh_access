

import json

PERMISSION_DEFINITIONS = [
    ("can_fetch_credentials", "Fetch OTP/SSH via API & Dashboard"),
    ("can_add_user", "Add New Users"),
    ("can_manage_users", "Manage Users (Edit/Delete/Regions)"),
    ("can_view_users_and_logs", "View User List & Audit Logs"),
]

PERMISSION_KEYS = [key for key, _ in PERMISSION_DEFINITIONS]

ALL_PERMISSIONS = {key: True for key in PERMISSION_KEYS}


def parse_permissions(raw):
    """Parse permissions from JSON string or dict."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return {}
    return {key: bool(data.get(key)) for key in PERMISSION_KEYS}


def permissions_from_form(form):
    """Build a permissions dict from a Flask request form."""
    return {key: bool(form.get(key)) for key in PERMISSION_KEYS}


def has_any_permission(perms, *names):
    if not perms:
        return False
    return any(perms.get(name) for name in names)


def has_subadmin_access(perms):
    """True when the employee has at least one SubAdmin privilege."""
    return has_any_permission(perms, *PERMISSION_KEYS)



