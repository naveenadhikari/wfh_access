import os
import logging

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

from flask import Flask, request, jsonify
from access_wfh_cfg import ACCESS_MANAGER_CONF
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__)
logger=logging.getLogger("")
logger.setLevel(logging.INFO)
consoleHandler=logging.StreamHandler()
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

def update_allowed_ips_for_web_access(access_type, ip_to_allow_log_access, emp_name):
    status = False
    cfg = get_access_cfg()
    cfg_file_path = cfg["webAccessConfig"][access_type]
    try:
        new_lines = []
        import re
        reg_ex_str = r'(allow[ ]+)([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})(; # ' + emp_name + ')'
        f = open(cfg_file_path)
        lines = f.readlines()
        found = False
        for ln in lines:
            rr = re.search(reg_ex_str, ln)
            if rr:
                found = True
                new_lines.append(rr.group(1) + ip_to_allow_log_access + rr.group(3).strip() + "\n")
            else:
                new_lines.append(ln)
        if not found:
            new_lines.insert(0, "allow " + ip_to_allow_log_access + "; # " + emp_name + "\n")
        f.close() 
        new_cfg_file_path = cfg_file_path + ".new"
        f = open(new_cfg_file_path, "w")
        for ln in new_lines:
            f.write(ln)
        f.close()
        logger.info("Updated")

        import subprocess
        command = "mv {} {} && /usr/bin/sudo -S /usr/sbin/nginx -s reload".format(new_cfg_file_path, cfg_file_path)
        op = subprocess.Popen([command], shell=True)
        status = True
    except Exception as e:
        logger.exception("Exception: {}".format(e))
    return status
def get_access_cfg():
    import importlib
    import access_wfh_cfg
    importlib.reload(access_wfh_cfg)
    return access_wfh_cfg.ACCESS_MANAGER_CONF

def open_port_for_hp_agent_access(emp_name, ip_to_allow):
    access_cfg = get_access_cfg()
    agent_cfg = access_cfg["hpAgentAccessConfig"]
    region_name = agent_cfg["region"]
    security_group_id = agent_cfg["securityGrpId"]
    return open_ports_for_acces(emp_name, ip_to_allow, agent_cfg["ports"], security_group_id, region_name)

def grant_authorized_access(emp_name, ip_to_allow):
    resp = {}
    
    # Check if we should run in Mock mode (default) for local testing without AWS/Nginx
    if os.environ.get("WFH_MOCK_ACCESS", "1") == "1":
        logger.info(f"[MOCK MODE] Granting access for {emp_name} at IP {ip_to_allow}")
        resp["logAccess"] = True
        resp["serverMetricsAccess"] = True
        resp["hpAgentAccess"] = {"openedCt": 1, "failedToOpenCt": 0, "alreadyOpenedCt": 0}
        resp["ports"] = {"openedCt": 1, "failedToOpenCt": 0, "alreadyOpenedCt": 0}
        return resp

    logger.info(f"[PRODUCTION MODE] Granting access for {emp_name} at IP {ip_to_allow}")
    access_cfg = get_access_cfg()
    
    # Check if the user is an admin or superadmin to grant full automatic access
    is_admin = False
    try:
        from db import get_admin
        if get_admin(emp_name):
            is_admin = True
    except Exception:
        pass

    if is_admin:
        # Admins automatically get full access to all logs, metrics, agent, regions, and default ports
        user_cfg = {
            "allowLogAccess": True,
            "allowServerMetricsAccess": True,
            "allowHpAgentAccess": True,
            "portsToOpen": [22, 3306, 80, 443, 1890],
            "overRiddenRegionAndCfg": None
        }
    else:
        user_cfg = access_cfg.get("ALLOWED_USR_IDENTITIES", {}).get(emp_name, {})
    
    if not user_cfg:
        logger.warning(f"User {emp_name} not found in configuration.")
        return resp

    # 1. Grant Log Access if allowed
    if user_cfg.get("allowLogAccess"):
        try:
            resp["logAccess"] = update_allowed_ips_for_web_access("logAccess", ip_to_allow, emp_name)
        except Exception as e:
            logger.exception("Failed to update log access: {}".format(e))
            resp["logAccess"] = False

    # 2. Grant Server Metrics Access if allowed
    if user_cfg.get("allowServerMetricsAccess"):
        try:
            resp["serverMetricsAccess"] = update_allowed_ips_for_web_access("metricAccess", ip_to_allow, emp_name)
        except Exception as e:
            logger.exception("Failed to update server metrics access: {}".format(e))
            resp["serverMetricsAccess"] = False

    # 3. Grant HP Agent Access if allowed
    if user_cfg.get("allowHpAgentAccess"):
        try:
            resp["hpAgentAccess"] = open_port_for_hp_agent_access(emp_name, ip_to_allow)
        except Exception as e:
            logger.exception("Failed to open HP Agent access: {}".format(e))
            resp["hpAgentAccess"] = {"openedCt": 0, "failedToOpenCt": 1, "alreadyOpenedCt": 0}

    # 4. Open regional ports (Global defaults or user-specific overrides)
    if user_cfg.get("portsToOpen") or user_cfg.get("overRiddenRegionAndCfg"):
        overridden_region_cfg = user_cfg.get("overRiddenRegionAndCfg")
        is_global_cfg = False
        if not overridden_region_cfg:
            is_global_cfg = True
            region_cfg = access_cfg.get("regionAndCfg", {}).copy()
            ports_to_open = user_cfg.get("portsToOpen", [])
        else:
            region_cfg = overridden_region_cfg
            
        # Iterate over configured regions and open corresponding Security Groups and ports
        for region_name, cfg in region_cfg.items():
            if not is_global_cfg:
                ports_to_open = cfg.get("portsToOpen", [])
            security_group_ids = cfg.get("securityGrpIds", [])
            for sg_id in security_group_ids:
                try:
                    resp["ports"] = open_ports_for_acces(emp_name, ip_to_allow, ports_to_open, sg_id, region_name)
                except Exception as e:
                    logger.exception(f"Failed to open ports in {region_name} for SG {sg_id}: {e}")
                    resp["ports"] = {"openedCt": 0, "failedToOpenCt": len(ports_to_open), "alreadyOpenedCt": 0}

    return resp

def get_data_from_request_inner(request):
    logger.info("Headers:{}".format(request.headers))
    ip_to_allow = request.headers.get("X-Forwarded-For")
    logger.info("IP to be allowed: {}".format(ip_to_allow))
    try:
        logger.info(dir(request))
        logger.info(request.data)
    except Exception as e:
        logger.exception(e)
    try:
        req_body = request.json
        logger.info("Got request : %s" % str(req_body))
        passw = req_body["password"]
        emp_name = req_body["name"]
        otp = req_body.get("otp")
        emp_name = emp_name.lower().replace(" ", "_")
    except Exception as e:
        logger.exception("EXC: {}".format(e))
    return emp_name, passw, otp, ip_to_allow

def open_ports_for_acces(emp_name, ip_to_allow, ports_to_open, security_group_id, region_name):
    status = False
    # ports_to_open = [22, 3306, 6379]
    ec2 = boto3.client('ec2', region_name)
    # Remove OLD allowed IP
    try:
        sec_grp_infos = ec2.describe_security_groups(GroupIds=[security_group_id])
        for sg in sec_grp_infos["SecurityGroups"]:
            for ip_perm in sg["IpPermissions"]:
                for ip_range in ip_perm["IpRanges"]:
                    if ip_range.get("Description") == emp_name:
                        # Use .get() with -1 as default for rules that allow all traffic
                        from_port = ip_perm.get("FromPort", -1)
                        to_port = ip_perm.get("ToPort", -1)
                        try:
                            ec2.revoke_security_group_ingress(
                                CidrIp=ip_range["CidrIp"],
                                FromPort=from_port,
                                GroupId=security_group_id,
                                IpProtocol='tcp',
                                ToPort=to_port,
                                DryRun=False
                                )
                            logger.info("Removed {}:{} for {}".format(ip_range["CidrIp"], ip_perm["FromPort"], emp_name))
                        except Exception as e:
                            pass
    except ClientError as e:
        logger.exception("Exception while removing old IP. {}".format(e))

    # Add new IP to white list.
    succeeded_ct = 0
    failed_ct = 0
    already_opened = 0
    for port_to_open in ports_to_open:
        try:
            data = ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': port_to_open,
                    'ToPort': port_to_open,
                    'IpRanges': [{'CidrIp': cidr_ip_to_allow, 'Description': emp_name}]},
                ])
            succeeded_ct += 1
            logger.info("Added {}:{} for {}".format(cidr_ip_to_allow, port_to_open, emp_name))
        except Exception as e:
            failed_ct += 1
            #if e.message.find("InvalidPermission.Duplicate"):
            if e.response['Error']['Code'] == "InvalidPermission.Duplicate":
                already_opened += 1
            logger.error("EXCEPTION: {}".format(e))
    resp = {"openedCt": succeeded_ct, "failedToOpenCt": failed_ct, "alreadyOpenedCt": already_opened}
    return resp

@app.route("/allow-access", methods=['POST'])
def allow_access():
    import pyotp
    response = {"status": False}
    emp_name, passw, user_sent_otp, ip_to_allow = get_data_from_request_inner(request)
    logger.info("EmpName: {} Pass:{} Otp: {}".format(emp_name, passw, user_sent_otp))
    cfg = get_access_cfg()
    error = "UnAuthorized.."
    status = False
    if emp_name in cfg["ALLOWED_USR_IDENTITIES"]:
        if cfg["ALLOWED_USR_IDENTITIES"][emp_name]["password"] == passw:
            otp_seed = cfg["ALLOWED_USR_IDENTITIES"][emp_name]["otpSeed"]
            totp = pyotp.TOTP(otp_seed)
            if totp.verify(user_sent_otp):
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


if __name__ == "__main__":
    import os
    PORT = os.environ.get("PORT", 6200)
    app.run(host='0.0.0.0', port=int(PORT))
