"""Password KDF, verification, and reset-token helpers.

Fixes applied:
- KDF parameters live in the record (`params`), and `needs_rehash` flags
  records whose params differ from the current policy so old hashes get
  upgraded on next login.
- pepper/salt composition order is fixed and documented:
  password input = pepper + password, salt input = salt. Never swapped.
- Hash and signature comparisons use hmac.compare_digest (constant time,
  no early return on length mismatch).
- Account keys are normalized with NFKC + casefold so 'Alice', 'alice'
  and full-width variants map to one identity.
- Reset tokens are HMAC-signed and expiry is verified server-side.
- Records carry a `version`; `verify` rejects stale versions so a
  concurrent password change cannot be overwritten by a later write.
"""

import base64
import hashlib
import hmac
import unicodedata

_DEFAULT_ITERATIONS = 100_000


def derive(password, salt, pepper, params):
    """Derive a hex digest from password/salt/pepper under `params`.

    Composition order is fixed: the pepper is prepended to the password
    (secret key material), the salt stands alone as the KDF salt.
    `params['n']` selects the iteration count.
    """
    if params is None:
        params = {}
    iterations = int(params.get('n', _DEFAULT_ITERATIONS))
    if iterations < 1:
        iterations = 1
    password = '' if password is None else str(password)
    salt = '' if salt is None else str(salt)
    pepper = '' if pepper is None else str(pepper)
    keyed = pepper + password  # pepper first, then password — do not swap
    digest = hashlib.pbkdf2_hmac(
        'sha256',
        keyed.encode('utf-8'),
        salt.encode('utf-8'),
        iterations,
    )
    return digest.hex()


def verify(password, record, version=None):
    """Check `password` against a stored record in constant time.

    Returns False for missing/malformed records, and False when `version`
    is supplied but does not match the record's version (stale write from
    a concurrent password change).
    """
    if not isinstance(record, dict):
        return False
    if version is not None and record.get('version') != version:
        return False
    stored = record.get('hash')
    salt = record.get('salt')
    pepper = record.get('pepper')
    params = record.get('params')
    if stored is None or salt is None or pepper is None or params is None:
        return False
    candidate = derive(password, salt, pepper, params)
    return hmac.compare_digest(str(stored), candidate)


def needs_rehash(record, current_params):
    """True when the record's KDF params differ from the current policy."""
    if not isinstance(record, dict):
        return True
    return record.get('params') != current_params


def normalize_username(username):
    """Canonical account key: NFKC fold + casefold + trim.

    'Alice', 'ALICE' and full-width 'Ａlice' all map to 'alice', so
    login-attempt counters and lookups cannot be dodged by case or
    unicode tricks.
    """
    if username is None:
        return ''
    return unicodedata.normalize('NFKC', str(username)).casefold().strip()


def _b64encode(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def _b64decode(data):
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(payload, secret):
    return hmac.new(
        str(secret).encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256,
    ).digest()


def make_reset_token(uid, expires, secret):
    """Signed reset token: base64url(uid.expires).base64url(hmac)."""
    payload = '{}.{}'.format(uid, int(expires))
    return _b64encode(payload.encode('utf-8')) + '.' + _b64encode(_sign(payload, secret))


def check_reset_token(token, secret, now):
    """Validate signature and expiry server-side. Never raises."""
    if not token or not isinstance(token, str):
        return False
    try:
        payload_b64, sig_b64 = token.split('.')
        payload = _b64decode(payload_b64).decode('utf-8')
        uid, expires = payload.rsplit('.', 1)
        if not uid:
            return False
        expires = int(expires)
        expected = _sign(payload, secret)
        if not hmac.compare_digest(_b64decode(sig_b64), expected):
            return False
    except Exception:
        return False
    return expires > now
