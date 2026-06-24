import json

allow_log = True
allow_metrics = False
allow_hp_agent = True
ports_to_open = [22, 80]
is_new_seed = True

details = {
    "allowLogAccess": allow_log,
    "allowServerMetricsAccess": allow_metrics,
    "allowHpAgentAccess": allow_hp_agent,
    "portsToOpen": ports_to_open,
    "otpSeedSource": "new" if is_new_seed else "existing",
}

print(json.dumps(details))
