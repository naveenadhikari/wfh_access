from db import (
    get_global_setting,
    get_all_wfh_users,
    wfh_user_exists,
    add_wfh_user,
    update_wfh_user,
)


def get_access_cfg():
    """
    Build the ACCESS_MANAGER_CONF dict fresh from the database every call.
    """
    cfg = {
        "regionAndCfg": get_global_setting("regionAndCfg", {}),
        "OTP_PREFIX": get_global_setting("OTP_PREFIX", ""),
        "OTP_VALID_FOR_SECS": get_global_setting("OTP_VALID_FOR_SECS", 300),
        "SMS_LANE_URL_PARAMS": get_global_setting("SMS_LANE_URL_PARAMS", {}),
        "webAccessConfig": get_global_setting("webAccessConfig", {}),
        "hpAgentAccessConfig": get_global_setting("hpAgentAccessConfig", {}),
        "ALLOWED_USR_IDENTITIES": {},
    }

    for username, u in get_all_wfh_users().items():
        user_entry = {
            "password": u["password_hash"],
            "otpSeed": u["otp_seed"],
            "allowLogAccess": bool(u["allow_log_access"]),
            "allowServerMetricsAccess": bool(u["allow_metrics_access"]),
            "allowHpAgentAccess": bool(u["allow_hp_agent_access"]),
        }
        if u["ports_to_open"]:
            user_entry["portsToOpen"] = u["ports_to_open"]

        if u["region_overrides"]:
            user_entry["overRiddenRegionAndCfg"] = u["region_overrides"]

        if u.get("admin_permissions"):
            user_entry["adminPermissions"] = u["admin_permissions"]

        cfg["ALLOWED_USR_IDENTITIES"][username] = user_entry

    return cfg


def add_user_to_config(username, user_entry):
    """
    Insert a new user into the database.

    user_entry: dict shaped like an ALLOWED_USR_IDENTITIES entry, e.g.
        {
            "password": "<bcrypt hash>",
            "otpSeed": "<seed>",
            "portsToOpen": [22],
            "allowLogAccess": True,
            "allowHpAgentAccess": True,
            "allowServerMetricsAccess": True,
            "overRiddenRegionAndCfg": {...}   # optional
        }
    """
    region_overrides = user_entry.get("overRiddenRegionAndCfg")

    add_wfh_user(
        username=username,
        password_hash=user_entry["password"],
        otp_seed=user_entry["otpSeed"],
        allow_log_access=user_entry.get("allowLogAccess", False),
        allow_metrics_access=user_entry.get("allowServerMetricsAccess", False),
        allow_hp_agent_access=user_entry.get("allowHpAgentAccess", False),
        ports_to_open=user_entry.get("portsToOpen", []),
        region_overrides=region_overrides,
        admin_permissions=user_entry.get("adminPermissions"),
    )


def update_user_in_config(username, user_entry):
    """
    Update an existing user in the database.
    """
    region_overrides = user_entry.get("overRiddenRegionAndCfg")

    update_wfh_user(
        username=username,
        allow_log_access=user_entry.get("allowLogAccess", False),
        allow_metrics_access=user_entry.get("allowServerMetricsAccess", False),
        allow_hp_agent_access=user_entry.get("allowHpAgentAccess", False),
        ports_to_open=user_entry.get("portsToOpen", []),
        region_overrides=region_overrides,
        admin_permissions=user_entry.get("adminPermissions"),
    )



def user_exists(username):
    return wfh_user_exists(username)


def list_users():
    """Return dict { username: user_entry } in the same shape as ALLOWED_USR_IDENTITIES."""
    return get_access_cfg()["ALLOWED_USR_IDENTITIES"]