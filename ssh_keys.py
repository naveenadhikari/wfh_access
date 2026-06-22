"""
Validation helpers for employee-uploaded SSH public keys.
"""

import re

SSH_KEY_TYPES = (
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
)

SSH_PUBLIC_KEY_RE = re.compile(
    r"^(?:" + "|".join(re.escape(t) for t in SSH_KEY_TYPES) + r") "
    r"[A-Za-z0-9+/=]+(?: .+)?$"
)


def normalize_ssh_public_key(raw_key):
    """Return a cleaned single-line public key, or None if invalid."""
    if not raw_key:
        return None

    key = raw_key.strip()
    if not key:
        return None

    key = key.splitlines()[0].strip()
    if len(key) > 8192:
        return None
    if not SSH_PUBLIC_KEY_RE.match(key):
        return None
    return key
