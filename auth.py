import bcrypt
import pyotp
from db import get_db


def hash_password(plain_password):
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def generate_otp_seed():
    return pyotp.random_base32()


def verify_otp_with_seed(user_sent_otp, seed):
    if not seed:
        return False
    totp = pyotp.TOTP(seed)
    return totp.verify(user_sent_otp)


def seed_admin(username, plain_password, otp_seed=None):
    conn = get_db()
    cur = conn.cursor()
    pw_hash = hash_password(plain_password)

    if otp_seed is None:
        otp_seed = generate_otp_seed()

    cur.execute("SELECT id, otp_seed FROM admins WHERE username = ?", (username,))
    existing = cur.fetchone()

    if existing:
        final_seed = otp_seed if otp_seed else existing["otp_seed"]
        cur.execute(
            "UPDATE admins SET password_hash = ?, otp_seed = ? WHERE username = ?",
            (pw_hash, final_seed, username)
        )
        print(f"Updated existing admin '{username}'")
        otp_seed = final_seed
    else:
        cur.execute(
            "INSERT INTO admins (username, password_hash, otp_seed) VALUES (?, ?, ?)",
            (username, pw_hash, otp_seed)
        )
        print(f"Created admin '{username}'")

    conn.commit()
    conn.close()
    return otp_seed


def verify_wfh_user(username, plain_password, user_sent_otp):
    """Authenticate a WFH employee using username, password, and OTP."""
    conn = get_db()
    row = conn.execute("SELECT * FROM wfh_users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None:
        return False
    if not check_password(plain_password, row["password_hash"]):
        return False
    if not verify_otp_with_seed(user_sent_otp, row["otp_seed"]):
        return False
    return True


def login_failure_reason(username, plain_password, user_sent_otp):
    """
    Diagnostics helper: return a short reason code explaining why a WFH-user
    login would fail — one of 'user_not_found', 'bad_password', 'bad_otp', or
    'ok'. Used only for logging; it never affects the auth decision.
    """
    conn = get_db()
    row = conn.execute("SELECT * FROM wfh_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row is None:
        return "user_not_found"
    if not check_password(plain_password, row["password_hash"]):
        return "bad_password"
    if not verify_otp_with_seed(user_sent_otp, row["otp_seed"]):
        return "bad_otp"
    return "ok"


def verify_admin(username, plain_password, user_sent_otp):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return False
    if not check_password(plain_password, row["password_hash"]):
        return False
    if not verify_otp_with_seed(user_sent_otp, row["otp_seed"]):
        return False
    return True


if __name__ == "__main__":
    import sys
    import getpass
    from db import init_db

    print("\n=== WFH Access Portal: Admin Provisioning Utility ===")
    init_db()

    try:
        # Prompt securely using getpass so passwords don't leak in shell history
        username = input("Enter admin username [default: admin]: ").strip() or "admin"
        password = getpass.getpass("Enter admin password: ")
        
        if not password:
            print("Error: Password cannot be empty.")
            sys.exit(1)

        confirm_password = getpass.getpass("Confirm admin password: ")
        if password != confirm_password:
            print("Error: Passwords do not match.")
            sys.exit(1)

        seed = seed_admin(username, password)
        totp = pyotp.TOTP(seed)
        uri = totp.provisioning_uri(name=username, issuer_name="WFH-Access")

        print("\n[SUCCESS] Admin account configured successfully!")
        print("==================================================")
        print(f" Username: {username}")
        print(f" OTP Seed: {seed}")
        print(f" Current Authenticator Code: {totp.now()}")
        print("==================================================")
        
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, border=2)
            qr.add_data(uri)
            qr.make(fit=True)
            print("\nScan this QR code with your Authenticator app:")
            qr.print_ascii()
        except Exception:
            print("\n(Note: Install 'qrcode' to render a scannable QR code directly in the terminal)")
            
        print("\nScan the QR code above or enter the secret seed manually into your Authenticator app.")
        print("Ensure you keep this seed secure.")
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)