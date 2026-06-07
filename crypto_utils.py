"""Symmetric encryption helpers for sensitive fields in CSV import/export.

A Fernet key is generated on first use and persisted in ``instance/cipher.key``
so that exports created by this installation can be re-imported later. The key
file should be treated as a secret and kept out of source control.
"""

import os
from cryptography.fernet import Fernet, InvalidToken

KEY_FILENAME = 'cipher.key'
INSTANCE_DIR = 'instance'
KEY_PATH = os.path.join(INSTANCE_DIR, KEY_FILENAME)


def _ensure_instance_dir(path: str) -> None:
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)


def get_or_create_key(path: str = KEY_PATH) -> bytes:
    """Return the Fernet key, creating a new one on disk if necessary."""
    _ensure_instance_dir(path)
    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, 'wb') as fh:
            fh.write(key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Permission tweaking is best-effort on Windows.
            pass
        return key

    with open(path, 'rb') as fh:
        return fh.read().strip()


_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(get_or_create_key())
    return _fernet


def encrypt_password(plaintext: str) -> str:
    """Encrypt a password into a Fernet token suitable for CSV storage."""
    if plaintext is None:
        plaintext = ''
    token = _get_fernet().encrypt(plaintext.encode('utf-8'))
    return token.decode('utf-8')


def decrypt_password(token: str) -> str | None:
    """Decrypt a Fernet token. Returns ``None`` when the token is invalid."""
    if not token:
        return ''
    try:
        plain = _get_fernet().decrypt(token.encode('utf-8'))
    except (InvalidToken, ValueError):
        return None
    return plain.decode('utf-8')
