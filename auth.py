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
    from db import init_db
    init_db()
    seed = seed_admin("admin", "admin123")
    print()
    print("Admin 'admin' created. Scan this seed into your authenticator app:")
    print("  Seed:", seed)
    print("  Current code:", pyotp.TOTP(seed).now())