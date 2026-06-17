"""
migrate_cfg_to_db.py
---------------------
ONE-TIME SCRIPT.

Reads the existing access_wfh_cfg.py file and copies all its data into the
new sqlite tables (wfh_users, wfh_user_region_overrides, global_settings).

After running this successfully, access_wfh_cfg.py is no longer needed for
storing user data -- the database becomes the source of truth.

Run once:
    python3 migrate_cfg_to_db.py

This script is SAFE TO RUN MULTIPLE TIMES on users that don't exist yet,
but will SKIP users that are already in the database (won't duplicate/overwrite).
"""

from access_wfh_cfg import ACCESS_MANAGER_CONF
from db import (
    set_global_setting,
    add_wfh_user,
    wfh_user_exists,
)


def main():
    cfg = ACCESS_MANAGER_CONF

    # --- 1. Migrate global settings ---
    global_keys = [
        "regionAndCfg",
        "webAccessConfig",
        "hpAgentAccessConfig",
        "OTP_PREFIX",
        "OTP_VALID_FOR_SECS",
        "SMS_LANE_URL_PARAMS",
    ]
    for key in global_keys:
        if key in cfg:
            set_global_setting(key, cfg[key])
            print(f"Migrated global setting: {key}")

    # --- 2. Migrate each WFH user ---
    users = cfg.get("ALLOWED_USR_IDENTITIES", {})
    migrated = 0
    skipped = 0

    for username, u in users.items():
        if wfh_user_exists(username):
            print(f"Skipping '{username}' - already in database.")
            skipped += 1
            continue

        # Build region_overrides dict in the shape add_wfh_user expects
        region_overrides = None
        if u.get("overRiddenRegionAndCfg"):
            region_overrides = {}
            for region, region_cfg in u["overRiddenRegionAndCfg"].items():
                region_overrides[region] = {
                    "securityGrpIds": region_cfg.get("securityGrpIds", []),
                    "portsToOpen": region_cfg.get("portsToOpen", []),
                }

        add_wfh_user(
            username=username,
            password_hash=u.get("password", ""),
            otp_seed=u.get("otpSeed", ""),
            allow_log_access=u.get("allowLogAccess", False),
            allow_metrics_access=u.get("allowServerMetricsAccess", False),
            allow_hp_agent_access=u.get("allowHpAgentAccess", False),
            ports_to_open=u.get("portsToOpen", []),
            region_overrides=region_overrides,
        )
        print(f"Migrated user: {username}")
        migrated += 1

    print()
    print(f"Done. Migrated {migrated} user(s), skipped {skipped} (already existed).")


if __name__ == "__main__":
    main()