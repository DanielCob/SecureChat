import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from securechat import keys


@pytest.fixture(scope="module")
def priv():
    return keys.generate_keypair()


def test_key_size_at_least_2048(priv):
    assert priv.key_size >= 2048
    with pytest.raises(ValueError):
        keys.generate_keypair(1024)


def test_pem_roundtrip_public(priv):
    pem = keys.public_key_to_pem(priv.public_key())
    assert b"BEGIN PUBLIC KEY" in pem
    assert keys.public_key_from_pem(pem).public_numbers() == priv.public_key().public_numbers()


def test_public_from_pem_rejects_weak_key():
    weak = rsa.generate_private_key(65537, 1024).public_key()
    from cryptography.hazmat.primitives import serialization as s
    pem = weak.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        keys.public_key_from_pem(pem)


def test_private_key_saved_with_owner_only_perms_and_reloads(priv, tmp_path):
    p = tmp_path / "k.pem"
    keys.save_private_key(priv, str(p))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    again = keys.load_private_key(str(p))
    assert again.private_numbers() == priv.private_numbers()


def test_load_or_create_is_idempotent(tmp_path):
    p = str(tmp_path / "x.pem")
    k1 = keys.load_or_create_keypair(p)
    k2 = keys.load_or_create_keypair(p)
    assert k1.private_numbers() == k2.private_numbers()


def test_fingerprint_stable_and_describe_hides_secret(priv):
    f = keys.fingerprint(priv.public_key())
    assert f == keys.fingerprint(priv.public_key()) and ":" in f
    d = keys.describe_private_key(priv)
    assert "PRIVATE" not in d and str(priv.private_numbers().d) not in d
