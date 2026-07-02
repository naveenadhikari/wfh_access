"""
ec2_provision.py
-----------------
Provisions a new Linux user on a target EC2 instance via SSH.

Does 4 things automatically:
  1. Creates the Linux user account
  2. Adds their SSH public key
  3. Configures Google Authenticator OTP for that user
  4. Ensures PAM + sshd are configured for key+OTP login (one-time per instance)

Called from your Flask add_user route — no IPs hardcoded here.
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


def run_cmd(client, command, use_sudo=True):
    """Run a command on the remote server. Returns (exit_code, stdout, stderr)."""
    full_cmd = f"sudo {command}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(full_cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return exit_code, out, err


# ─────────────────────────────────────────────
# STEP 1 — CREATE LINUX USER
# ─────────────────────────────────────────────

def create_linux_user(client, username):
    exit_code, out, err = run_cmd(client, f"id {username}", use_sudo=False)
    if exit_code == 0:
        print(f"  [SKIP] User '{username}' already exists")
        return True

    exit_code, out, err = run_cmd(client, f"useradd -m -s /bin/bash {username}")
    if exit_code != 0:
        print(f"  [FAIL] Could not create user: {err}")
        return False

    print(f"  [OK] Created Linux user '{username}'")
    return True


# ─────────────────────────────────────────────
# STEP 2 — ADD SSH PUBLIC KEY (via SFTP)
# ─────────────────────────────────────────────

def add_ssh_key(client, username, ssh_public_key):
    ssh_public_key = ssh_public_key.strip()

    # Create .ssh directory with correct permissions and enforce home dir permissions
    for cmd in [
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
                                key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER):
    """
    Full provisioning flow.
    Call this from your Flask route — pass the instance IP from the dropdown selection.
    Returns a dict with status of each step.
    """
    result = {
        "success": False,
        "linux_user_created": False,
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
        result["linux_user_created"] = create_linux_user(client, username)
        if not result["linux_user_created"]:
            client.close()
            return result

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


def revoke_user_on_instance(public_ip, username, key_path=MASTER_KEY_PATH, ssh_user=MASTER_SSH_USER):
    """
    Revoke a user's access on an EC2 instance by deleting their Linux account and home directory.
    Returns (success_bool, error_msg).
    """
    try:
        print(f"\nRevoking access for '{username}' on {public_ip}...")
        client = connect_to_instance(public_ip, key_path, ssh_user)
        
        # Kill any active sessions for the user to ensure userdel works
        run_cmd(client, f"pkill -u {username}")
        
        # Delete user and their home directory (-r removes home dir + mail spool)
        exit_code, out, err = run_cmd(client, f"userdel -r {username}")
        client.close()
        
        if exit_code == 0 or "does not exist" in err.lower():
            print(f"  [OK] Access revoked for '{username}'")
            return True, None
        else:
            print(f"  [FAIL] Could not revoke user: {err}")
            return False, err
            
    except Exception as e:
        print(f"\n[ERROR revoking] {e}")
        return False, str(e)


# ─────────────────────────────────────────────
# MANUAL TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import pyotp
    TEST_INSTANCE_IP = "3.0.18.89"
    TEST_USERNAME      = "testemployee"
    TEST_SSH_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDhctS6Ha1BTdhUoexkD/suLU4/dDQt3XN8NUqa5HHkkCCTxP4IsdC/uP/leuSuciRS29WMz+FqiQJHy8OiZMLw4ZGrG922l+98hd+JLUBVHnpdWe6ZYHv2/o/ZXLcZno1v0vb+RmqpM5UojbCzG0jx7hq1Iu6vWL5odNO5ZcF2sycf+3DCvdRsZaj9zI5rEnbJa8fbsNqtgFOTIs1oQBs7+sfEQueWiZ9qPOBnYNJa+zhAEpaTbTxpAQvTerVsjSkv7oTzWQftmCjhJBr5D5s/A3iOKoIvWZNxCqXFErYQ1IR8yo+xUpKhFA2k8YbBgXhM9ElJV7A43Jt039feS+4XA2Rd4VDUoUsJTM1/rx89MYl9hCC+CCBZfKVQxy0dsyXUUgRukaMIsxEsFx+MDLbpVNid5O+wayXfAIOQIP1gr4UvoADStmAkTe6eVr/WiQp6QENM0LTxn6n9PxV1aYDHwtbCjdWnexna+o4MLJJb6UtqZ2lGX4oQzv5XhLIZBdPKi2vASEjsZDDoc9kVPyO0r+ikP+wGmHbE+fLShj/TE64YtOZbHC2IG6C/NeFJlr+Z8ZXZ2/iQNhwmgG3RS4bRrsT+dvVGQID1+B9B/9lAAMvB4nNOwhGZ+iS+xVFVhakV3qrtwLIzs/NkGxoFYXvwetb26dmJ+M0yfl8aiWOPvw== naveen@INT214Naveen"
    TEST_OTP_SEED      = pyotp.random_base32()

    print("="*60)
    print("EC2 PROVISIONING TEST")
    print(f"Target:   {TEST_INSTANCE_IP}")
    print(f"User:     {TEST_USERNAME}")
    print(f"OTP seed: {TEST_OTP_SEED}")
    print("="*60)

    result = provision_user_on_instance(
        public_ip=TEST_INSTANCE_IP,
        username=TEST_USERNAME,
        ssh_public_key=TEST_SSH_PUBLIC_KEY,
        otp_seed=TEST_OTP_SEED,
    )

    print("\n" + "="*60)
    print("RESULT:", result)
    print("="*60)

    if result["success"]:
        print(f"\nTest login:")
        print(f"  ssh -i /tmp/test_employee_key {TEST_USERNAME}@{TEST_INSTANCE_IP}")
        print(f"\nOTP code right now:")
        print(f"  {pyotp.TOTP(TEST_OTP_SEED).now()}")