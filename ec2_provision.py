"""
ec2_provision.py
  1. Creates the Linux user account
  2. Adds their SSH public key
  3. Configures Google Authenticator OTP for that user
  4. Ensures PAM + sshd are configured for key+OTP login (one-time per instance)

"""
import paramiko
import os


def load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip().strip("'\"")

load_env_file()

MASTER_KEY_PATH = os.environ.get("MASTER_KEY_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys", "test-key.pem"))
MASTER_SSH_USER = os.environ.get("MASTER_SSH_USER", "ubuntu")


# ─────────────────────────────────────────────
# SSH CONNECTION
# ─────────────────────────────────────────────

def connect_to_instance(public_ip, key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(hostname=public_ip, username=ssh_user, pkey=key, timeout=timeout)
    return client


def run_cmd(client, command, use_sudo=True, timeout=20):
    """Run a command on the remote server. Returns (exit_code, stdout, stderr).

    Raises socket.timeout if the command doesn't finish within `timeout` seconds,
    instead of blocking forever (e.g. instance became unreachable mid-command,
    or a command like `userdel` is stuck waiting on something remote).
    """
    full_cmd = f"sudo {command}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
    stdout.channel.settimeout(timeout)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return exit_code, out, err


# ─────────────────────────────────────────────
# STEP 1 — CREATE LINUX USER
# ─────────────────────────────────────────────

# Whitelist of groups that can ever be passed to useradd/usermod for a
# provisioned employee. Group names flow into a shell command over SSH, so
# NEVER accept arbitrary/free-text group names here — only ever pass values
# that have already been checked against this set.
ALLOWED_LINUX_GROUPS = {"adm", "www-data", "claude-users", "sudo"}


def _sanitize_groups(groups):
    """Keep only whitelisted, safe group names. Silently drops anything else."""
    if not groups:
        return []
    return [g for g in groups if g in ALLOWED_LINUX_GROUPS]


def create_linux_user(client, username, groups=None):
    groups = _sanitize_groups(groups)
    group_csv = ",".join(groups)

    exit_code, out, err = run_cmd(client, f"id {username}", use_sudo=False)
    if exit_code == 0:
        print(f"  [SKIP] User '{username}' already exists. Enforcing /bin/bash shell.")
        run_cmd(client, f"usermod -s /bin/bash {username}")
        if groups:
            exit_code, out, err = run_cmd(client, f"usermod -a -G {group_csv} {username}")
            if exit_code != 0:
                print(f"  [FAIL] Could not update groups for '{username}': {err}")
                return False
            print(f"  [OK] Groups ensured for '{username}': {group_csv}")
        return True

    group_arg = f" -G {group_csv}" if groups else ""
    exit_code, out, err = run_cmd(client, f"useradd -m -s /bin/bash{group_arg} {username}")
    if exit_code != 0:
        print(f"  [FAIL] Could not create user: {err}")
        return False

    print(f"  [OK] Created Linux user '{username}'" + (f" with groups: {group_csv}" if groups else ""))
    return True


def set_initial_password(client, username):
   
    payload = f"{username}:{username}\n"
    tmp_path = f"/tmp/{username}_chpasswd_tmp"

    sftp = client.open_sftp()
    with sftp.file(tmp_path, "w") as f:
        f.write(payload)
    sftp.close()

    exit_code, out, err = run_cmd(client, f"bash -c 'chpasswd < {tmp_path}'")
    run_cmd(client, f"rm -f {tmp_path}")

    if exit_code != 0:
        print(f"  [FAIL] Could not set initial password for '{username}': {err}")
        return False

    print(f"  [OK] Initial password set for '{username}' (password == username)")
    return True


# ─────────────────────────────────────────────
# STEP 2 — ADD SSH PUBLIC KEY 
# ─────────────────────────────────────────────

def add_ssh_key(client, username, ssh_public_key):
    ssh_public_key = ssh_public_key.strip()

    # Create .ssh directory with correct permissions and enforce home dir permissions
    for cmd in [
        f"mkdir -p /home/{username}",
        f"chown {username}:{username} /home/{username}",
        f"chmod 755 /home/{username}",
        f"mkdir -p /home/{username}/.ssh",
        f"chmod 700 /home/{username}/.ssh",
        f"chown {username}:{username} /home/{username}/.ssh",
    ]:
        exit_code, out, err = run_cmd(client, cmd)
        if exit_code != 0:
            print(f"  [FAIL] {cmd} → {err}")
            return False

    # Write key via SFTP — avoids all shell quoting issues with special characters
    tmp_path = f"/tmp/{username}_pubkey_tmp"
    sftp = client.open_sftp()
    with sftp.file(tmp_path, "w") as f:
        f.write(ssh_public_key + "\n")
    sftp.close()

    # Move into place with correct ownership and permissions (using cp to preserve correct SELinux contexts)
    for cmd in [
        f"cp {tmp_path} /home/{username}/.ssh/authorized_keys",
        f"rm -f {tmp_path}",
        f"chown {username}:{username} /home/{username}/.ssh/authorized_keys",
        f"chmod 600 /home/{username}/.ssh/authorized_keys",
        f"command -v restorecon >/dev/null 2>&1 && restorecon -Rv /home/{username}/.ssh || true",
    ]:
        exit_code, out, err = run_cmd(client, cmd)
        if exit_code != 0:
            print(f"  [FAIL] {cmd} → {err}")
            return False

    print(f"  [OK] SSH public key added for '{username}'")
    return True


# ─────────────────────────────────────────────
# STEP 3 — CONFIGURE OTP FOR THIS USER
# ─────────────────────────────────────────────

def setup_user_otp(client, username, otp_seed):
    """Write the OTP seed to the user's .google_authenticator file."""

    # Detect OS
    exit_code, os_release, _ = run_cmd(client, "cat /etc/os-release", use_sudo=False)
    is_rhel = "ID=\"amzn\"" in os_release or "ID=\"centos\"" in os_release or "ID=\"rhel\"" in os_release

    # Install google-authenticator if not already present
    if is_rhel:
        exit_code, _, _ = run_cmd(client, "rpm -q google-authenticator")
        if exit_code != 0:
            print("  [INFO] Installing google-authenticator (RHEL/Amazon Linux)...")
            # EPEL may be needed on CentOS/RHEL, but usually available on Amazon Linux 2023 natively
            run_cmd(client, "yum install -y epel-release")
            exit_code, out, err = run_cmd(client, "yum install -y google-authenticator")
            if exit_code != 0:
                print(f"  [FAIL] Could not install package: {err}")
                return False
            print("  [OK] google-authenticator installed")
        else:
            print("  [SKIP] google-authenticator already installed")
    else:
        exit_code, _, _ = run_cmd(client, "dpkg -l | grep -q libpam-google-authenticator")
        if exit_code != 0:
            print("  [INFO] Installing libpam-google-authenticator (Debian/Ubuntu)...")
            run_cmd(client, "apt-get update -y")
            exit_code, out, err = run_cmd(
                client, "DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-google-authenticator"
            )
            if exit_code != 0:
                print(f"  [FAIL] Could not install package: {err}")
                return False
            print("  [OK] libpam-google-authenticator installed")
        else:
            print("  [SKIP] libpam-google-authenticator already installed")

    # Write OTP config file via SFTP — same approach as SSH key to avoid quoting issues
    ga_content = f"{otp_seed}\n\" RATE_LIMIT 3 30\n\" DISALLOW_REUSE\n\" TOTP_AUTH\n"
    tmp_path = f"/tmp/{username}_google_auth_tmp"

    sftp = client.open_sftp()
    with sftp.file(tmp_path, "w") as f:
        f.write(ga_content)
    sftp.close()

    for cmd in [
        f"cp {tmp_path} /home/{username}/.google_authenticator",
        f"rm -f {tmp_path}",
        f"chown {username}:{username} /home/{username}/.google_authenticator",
        f"chmod 400 /home/{username}/.google_authenticator",
    ]:
        exit_code, out, err = run_cmd(client, cmd)
        if exit_code != 0:
            print(f"  [FAIL] {cmd} → {err}")
            return False

    print(f"  [OK] OTP configured for '{username}'")
    return True


# ─────────────────────────────────────────────
# STEP 4 — CONFIGURE PAM + SSHD (one-time per instance)
# ─────────────────────────────────────────────

def configure_instance_for_otp(client, master_user="ubuntu"):
    """
    One-time setup per instance.
    - Enables Google Authenticator in PAM with nullok
    - Enables keyboard-interactive in sshd
    - Uses Match block so master user (ubuntu) never needs OTP
    - Tests config before restarting sshd
    """
    # Check if already configured
    exit_code, _, _ = run_cmd(
        client, "grep -q 'pam_google_authenticator' /etc/pam.d/sshd", use_sudo=False
    )
    if exit_code == 0:
        print("  [SKIP] PAM already configured for OTP")
    else:
        run_cmd(client, "sed -i 's/@include common-auth/#@include common-auth/' /etc/pam.d/sshd")
        run_cmd(client, "bash -c 'echo \"auth required pam_google_authenticator.so nullok\" >> /etc/pam.d/sshd'")
        print("  [OK] PAM configured for OTP")

    # Check if sshd already configured
    exit_code, _, _ = run_cmd(
        client, "grep -q 'AuthenticationMethods publickey,keyboard-interactive' /etc/ssh/sshd_config",
        use_sudo=False
    )
    if exit_code == 0:
        print("  [SKIP] sshd already configured for key+OTP")
    else:
        run_cmd(client, "sed -i 's/KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config")
        # Add AuthenticationMethods with Match block for master user
        sshd_addition = (
            f"AuthenticationMethods publickey,keyboard-interactive\\n"
            f"Match User {master_user}\\n"
            f"    AuthenticationMethods publickey"
        )
        run_cmd(client, f"bash -c 'echo -e \"{sshd_addition}\" >> /etc/ssh/sshd_config'")
        print("  [OK] sshd configured — master user excluded from OTP")

    # Test config before restarting
    exit_code, out, err = run_cmd(client, "sshd -t")
    if exit_code != 0:
        print(f"  [FAIL] sshd config test failed: {err}")
        return False

    # Detect OS to restart correct service
    exit_code, os_release, _ = run_cmd(client, "cat /etc/os-release", use_sudo=False)
    is_rhel = "ID=\"amzn\"" in os_release or "ID=\"centos\"" in os_release or "ID=\"rhel\"" in os_release
    ssh_service = "sshd" if is_rhel else "ssh"

    exit_code, out, err = run_cmd(client, f"systemctl restart {ssh_service}")
    if exit_code != 0:
        print(f"  [FAIL] Could not restart {ssh_service}: {err}")
        return False

    print(f"  [OK] {ssh_service} restarted — OTP active for employees only")
    return True
# ─────────────────────────────────────────────
# MAIN — called from Flask add_user route
# ─────────────────────────────────────────────

def provision_user_on_instance(public_ip, username, ssh_public_key, otp_seed,
                                key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER,
                                groups=None, set_password=True):
    """
    Full provisioning flow.
    Call this from your Flask route — pass the instance IP from the dropdown selection.
    `groups` is an optional list of Linux group names (must be in ALLOWED_LINUX_GROUPS)
    the new user should also be added to, e.g. ["adm", "www-data", "claude-users"].
    `set_password`: if True (default), sets the account's initial Unix password
    to the username itself, matching the original bash script's behavior.
    Returns a dict with success status and details of each step.
    """
    result = {
        "success": False,
        "linux_user_created": False,
        "password_set": None,
        "ssh_key_added": False,
        "otp_configured": False,
        "instance_configured": False,
        "error": None,
    }

    try:
        print(f"\nConnecting to {public_ip}...")
        client = connect_to_instance(public_ip, key_path, ssh_user)
        print("  [OK] Connected\n")

        print(f"Step 1: Creating Linux user '{username}'...")
        result["linux_user_created"] = create_linux_user(client, username, groups=groups)
        if not result["linux_user_created"]:
            client.close()
            return result

        if set_password:
            print(f"\nStep 1b: Setting initial password for '{username}'...")
            # Non-blocking — if this fails, provisioning continues since the
            # intended login path is SSH key + OTP, not the password.
            result["password_set"] = set_initial_password(client, username)

        print(f"\nStep 2: Adding SSH public key...")
        result["ssh_key_added"] = add_ssh_key(client, username, ssh_public_key)
        if not result["ssh_key_added"]:
            client.close()
            return result

        print(f"\nStep 3: Setting up OTP for user...")
        result["otp_configured"] = setup_user_otp(client, username, otp_seed)
        if not result["otp_configured"]:
            client.close()
            return result

        print(f"\nStep 4: Configuring instance for key+OTP login (one-time)...")
        result["instance_configured"] = configure_instance_for_otp(client)
        # result["instance_configured"] = True

        client.close()

        result["success"] = all([
            result["linux_user_created"],
            result["ssh_key_added"],
            result["otp_configured"],
            result["instance_configured"],
        ])
        return result

    except Exception as e:
        result["error"] = str(e)
        print(f"\n[ERROR] {e}")
        return result


def revoke_user_on_instance(public_ip, username, key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER,
                             connect_timeout=15, cmd_timeout=20):
    """
    Revoke a user's access on an EC2 instance by deleting their Linux account and home directory.
    Returns (success_bool, error_msg).

    connect_timeout: max seconds to wait for the SSH connection itself (instance unreachable/stopped).
    cmd_timeout: max seconds to wait for each remote command to finish.
    """
    import socket

    client = None

    # ── Phase 1: connect ──
    try:
        print(f"\nRevoking access for '{username}' on {public_ip}...")
        client = connect_to_instance(public_ip, key_path, ssh_user, timeout=connect_timeout)
    except (socket.timeout, TimeoutError):
        msg = (
            f"Timed out connecting to {public_ip} within {connect_timeout}s. "
            "The instance is likely stopped/terminated, its public IP changed after a "
            "restart, or its security group no longer allows SSH (port 22) from this admin server."
        )
        print(f"\n[ERROR revoking] {msg}")
        return False, msg
    except paramiko.AuthenticationException:
        msg = "SSH authentication to the instance failed (check the master key/user)."
        print(f"\n[ERROR revoking] {msg}")
        return False, msg
    except Exception as e:
        print(f"\n[ERROR revoking] Connection failed: {e}")
        return False, f"Connection failed: {e}"

    # ── Phase 2: run commands ──
    try:
        # Kill any active sessions for the user to ensure userdel works.
        # Don't fail the whole revoke if this step errors — pkill returns
        # non-zero if the user has no running processes, which is normal.
        try:
            run_cmd(client, f"pkill -u {username}", timeout=cmd_timeout)
        except (socket.timeout, TimeoutError):
            print(f"  [WARN] pkill step timed out after {cmd_timeout}s (continuing)")
        except Exception as e:
            print(f"  [WARN] pkill step failed (continuing): {e}")

        # Delete user and their home directory (-r removes home dir + mail spool)
        exit_code, out, err = run_cmd(client, f"userdel -r {username}", timeout=cmd_timeout)

        if exit_code == 0 or "does not exist" in err.lower():
            print(f"  [OK] Access revoked for '{username}'")
            return True, None
        elif "currently used by process" in err.lower() or "user busy" in err.lower():
            # One retry after a harder kill and a short pause.
            print(f"  [INFO] User has active processes, retrying with SIGKILL: {err}")
            run_cmd(client, f"pkill -9 -u {username}", timeout=cmd_timeout)
            run_cmd(client, "sleep 2", use_sudo=False, timeout=cmd_timeout)
            exit_code, out, err = run_cmd(client, f"userdel -r {username}", timeout=cmd_timeout)
            if exit_code == 0:
                print(f"  [OK] Access revoked for '{username}' (after force kill)")
                return True, None
            print(f"  [FAIL] Still could not revoke user after force kill: {err}")
            return False, f"User '{username}' still has running/logged-in sessions on the instance. Ask them to log out and try again."
        else:
            print(f"  [FAIL] Could not revoke user: {err}")
            return False, err

    except (socket.timeout, TimeoutError):
        msg = (
            f"Connected to {public_ip} successfully, but a command (pkill/userdel) took longer "
            f"than {cmd_timeout}s to respond. This usually means the instance is under heavy load, "
            "or something on it (e.g. a slow-to-delete home directory) is stuck."
        )
        print(f"\n[ERROR revoking] {msg}")
        return False, msg
    except Exception as e:
        print(f"\n[ERROR revoking] {e}")
        return False, str(e)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


# ─────────────────────────────────────────────
# EDIT GROUPS 
# ─────────────────────────────────────────────

def _reconcile_groups(client, username, desired_groups):
    """
    Make the user's membership in ALLOWED_LINUX_GROUPS match `desired_groups`
    exactly — adds any allowed group that's missing, removes any allowed
    group that's no longer wanted. Groups outside ALLOWED_LINUX_GROUPS
    are never touched.

    Returns (success_bool, details_dict) where details_dict has
    "added", "removed", and "failed" lists.
    """
    desired = set(_sanitize_groups(desired_groups))

    exit_code, out, err = run_cmd(client, f"id -nG {username}", use_sudo=False)
    if exit_code != 0:
        return False, {"added": [], "removed": [], "failed": [], "error": f"Could not read current groups: {err}"}

    current = set(out.split())
    to_add = sorted(desired - current)
    to_remove = sorted((current & ALLOWED_LINUX_GROUPS) - desired)

    details = {"added": [], "removed": [], "failed": []}

    for grp in to_add:
        exit_code, out, err = run_cmd(client, f"usermod -a -G {grp} {username}")
        if exit_code == 0:
            details["added"].append(grp)
        else:
            details["failed"].append({"group": grp, "action": "add", "error": err})

    for grp in to_remove:
        exit_code, out, err = run_cmd(client, f"gpasswd -d {username} {grp}")
        if exit_code == 0:
            details["removed"].append(grp)
        else:
            details["failed"].append({"group": grp, "action": "remove", "error": err})

    success = len(details["failed"]) == 0
    return success, details


def update_user_groups_on_instance(public_ip, username, groups,
                                     key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER,
                                     connect_timeout=15):
    """
    Connect to an instance and reconcile a user's Linux group membership to
    exactly match `groups` (a list from ALLOWED_LINUX_GROUPS). Use this for
    an admin editing an existing provision's privileges without a full
    re-provision (no SSH key / OTP / sshd changes — just group membership).

    Returns (success_bool, details_dict_or_error_message).
    """
    import socket

    client = None
    try:
        client = connect_to_instance(public_ip, key_path, ssh_user, timeout=connect_timeout)
    except (socket.timeout, TimeoutError):
        return False, f"Timed out connecting to {public_ip} within {connect_timeout}s."
    except paramiko.AuthenticationException:
        return False, "SSH authentication to the instance failed (check the master key/user)."
    except Exception as e:
        return False, f"Connection failed: {e}"

    try:
        exit_code, out, err = run_cmd(client, f"id {username}", use_sudo=False)
        if exit_code != 0:
            return False, f"User '{username}' does not exist on this instance."

        success, details = _reconcile_groups(client, username, groups)
        return success, details
    except (socket.timeout, TimeoutError):
        return False, "Connected, but a command timed out while updating groups."
    except Exception as e:
        return False, str(e)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass