"""
Token-based authentication for the WFH Access API.

The app no longer uses Flask's cookie `session`. Instead, clients authenticate
by sending the token issued at login in the `X-AUTH-TOKEN` request header. The
token maps (via the `auth_sessions` table) to an actor: either an admin or a
WFH employee, together with their role/permissions.

Decorators here gate API endpoints and always respond with JSON, never a
redirect — the browser UI lives in a separate SPA that handles routing itself.
"""

import functools

from flask import request, jsonify, g

from db import get_auth_session, get_wfh_user
from permissions import ALL_PERMISSIONS

TOKEN_HEADER = "X-AUTH-TOKEN"


def _load_identity():
    """
    Resolve the current actor from the X-AUTH-TOKEN header exactly once per
    request, caching the result on flask.g. Returns a dict or None.

    Permissions are resolved LIVE from the source of truth on every request
    (not snapshotted into the session at login). This means an admin changing a
    subadmin's privileges takes effect on the subadmin's very next request —
    both grants and revocations — without forcing them to log in again.
    """
    if "identity" in g:
        return g.identity

    token = request.headers.get(TOKEN_HEADER)
    identity = None
    if token:
        sess = get_auth_session(token)
        if sess:
            actor_type = sess["actor_type"]
            username = sess["username"]
            if actor_type == "employee":
                # Live lookup — reflects the current admin_permissions immediately.
                db_user = get_wfh_user(username) or {}
                permissions = db_user.get("admin_permissions") or {}
            else:
                # Admins are always full-access (see effective_permissions).
                permissions = sess.get("permissions") or {}
            identity = {
                "token": token,
                "actor_type": actor_type,
                "username": username,
                "role": sess.get("role"),
                "permissions": permissions,
            }
    g.identity = identity
    return identity


def current_identity():
    """Public accessor for the resolved identity (or None)."""
    return _load_identity()


def is_admin_actor(identity):
    """
    True for a full admin account. There is only one admin tier and it always
    holds every privilege — there is no separate 'superadmin' role. Elevated
    employees ('subadmins') are NOT admins; they carry explicit permissions.
    """
    return bool(identity and identity["actor_type"] == "admin")


def effective_permissions(identity):
    """Admins implicitly hold every permission; employees hold only what they were granted."""
    if not identity:
        return {}
    if is_admin_actor(identity):
        return ALL_PERMISSIONS
    return identity.get("permissions") or {}


def _unauthorized():
    return jsonify({"error": "Unauthorized", "code": "no_token"}), 401


def token_required(view_func):
    """Any authenticated actor (admin or employee)."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if not _load_identity():
            return _unauthorized()
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """Admin actors only (any role)."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        ident = _load_identity()
        if not ident:
            return _unauthorized()
        if ident["actor_type"] != "admin":
            return jsonify({"error": "Forbidden: admin access required"}), 403
        return view_func(*args, **kwargs)
    return wrapped


def employee_required(view_func):
    """Employee actors only."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        ident = _load_identity()
        if not ident:
            return _unauthorized()
        if ident["actor_type"] != "employee":
            return jsonify({"error": "Forbidden: employee access required"}), 403
        return view_func(*args, **kwargs)
    return wrapped


def require_permission(*perm_names):
    """
    Allow the request if the actor holds ANY of the named permissions.
    Admins always pass (they hold every privilege). Permissioned employees
    (subadmins) are accepted when they hold one of the named permissions.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(*args, **kwargs):
            ident = _load_identity()
            if not ident:
                return _unauthorized()
            if is_admin_actor(ident):
                return view_func(*args, **kwargs)
            perms = effective_permissions(ident)
            if any(perms.get(p) for p in perm_names):
                return view_func(*args, **kwargs)
            return jsonify({
                "error": f"Forbidden: missing permission ({' or '.join(perm_names)})"
            }), 403
        return wrapped
    return decorator
