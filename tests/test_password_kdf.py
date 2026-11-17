import pytest

from auth.password_kdf import (
    derive,
    verify,
    needs_rehash,
    normalize_username,
    make_reset_token,
    check_reset_token
)


def test_derive_deterministic():
    assert derive('pw', 'salt', 'pepper', {'n': 2}) == derive('pw', 'salt', 'pepper', {'n': 2})

def test_derive_salt():
    assert derive('pw', 'salt1', 'pepper', {'n': 2}) != derive('pw', 'salt2', 'pepper', {'n': 2})

def test_derive_pepper():
    assert derive('pw', 'salt', 'p1', {'n': 2}) != derive('pw', 'salt', 'p2', {'n': 2})

def test_verify_true():
    assert verify('pw', {'hash': derive('pw', 'salt', 'pepper', {'n': 2}), 'salt': 'salt', 'pepper': 'pepper', 'params': {'n': 2}}) is True

def test_verify_false():
    assert verify('bad', {'hash': derive('pw', 'salt', 'pepper', {'n': 2}), 'salt': 'salt', 'pepper': 'pepper', 'params': {'n': 2}}) is False

def test_verify_missing():
    assert verify('pw', {}) is False

def test_rehash_old():
    assert needs_rehash({'params': {'n': 2}}, {'n': 4}) is True

def test_rehash_current():
    assert needs_rehash({'params': {'n': 4}}, {'n': 4}) is False

def test_normalize_lower():
    assert normalize_username('Alice') == 'alice'

def test_normalize_unicode():
    assert normalize_username('Ａlice') == 'alice'

def test_reset_valid():
    assert check_reset_token(make_reset_token('u1', 200, 'secret'), 'secret', 100) is True

def test_reset_expired():
    assert check_reset_token(make_reset_token('u1', 90, 'secret'), 'secret', 100) is False

def test_reset_tamper():
    assert check_reset_token(make_reset_token('u1', 200, 'secret') + 'x', 'secret', 100) is False

def test_concurrent_version():
    assert verify('pw', {'hash': derive('pw', 's', 'p', {'n': 2}), 'salt': 's', 'pepper': 'p', 'params': {'n': 2}, 'version': 1}, version=2) is False

def test_empty_password():
    assert derive('', 's', 'p', {'n': 2}) is not None
