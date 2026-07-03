import pytest

from holler.crypto import (
    LamportClock,
    PairwiseHandshake,
    SeenCache,
    open_any,
    open_sealed,
    rand_id,
    seal,
)
from holler.errors import AuthenticationError


def _run_handshake(password_a: bytes, password_b: bytes):
    a = PairwiseHandshake(password_a)
    b = PairwiseHandshake(password_b)
    spake_a, pub_a = a.outbound()
    spake_b, pub_b = b.outbound()
    return a.finish(spake_b, pub_b), b.finish(spake_a, pub_a)


def test_handshake_same_password_agrees():
    crypto_a, crypto_b = _run_handshake(b"secret", b"secret")
    assert crypto_a.verify_confirmation("peer-a", crypto_a.confirmation("peer-a"))
    assert crypto_b.verify_confirmation("peer-a", crypto_a.confirmation("peer-a"))
    blob = crypto_a.encrypt(b"hello", b"aad")
    assert crypto_b.decrypt(blob, b"aad") == b"hello"


def test_handshake_wrong_password_fails_confirmation():
    crypto_a, crypto_b = _run_handshake(b"secret", b"wrong")
    mac = crypto_a.confirmation("peer-a")
    assert not crypto_b.verify_confirmation("peer-a", mac)


def test_confirmation_is_direction_bound():
    crypto_a, _ = _run_handshake(b"secret", b"secret")
    mac = crypto_a.confirmation("peer-a")
    # Reflecting a MAC back under the other identity must fail.
    assert not crypto_a.verify_confirmation("peer-b", mac)


def test_handshake_rejects_reflected_message():
    a = PairwiseHandshake(b"secret")
    spake_a, pub_a = a.outbound()
    with pytest.raises(AuthenticationError):
        a.finish(spake_a, pub_a)


def test_seal_roundtrip_and_aad_binding():
    key = b"k" * 32
    blob = seal(key, b"payload", b"context")
    assert open_sealed(key, blob, b"context") == b"payload"
    with pytest.raises(AuthenticationError):
        open_sealed(key, blob, b"tampered")
    with pytest.raises(AuthenticationError):
        open_sealed(b"x" * 32, blob, b"context")


def test_open_any_tries_multiple_keys():
    old, new = b"o" * 32, b"n" * 32
    blob = seal(old, b"data", b"aad")
    assert open_any([new, old], blob, b"aad") == b"data"
    with pytest.raises(AuthenticationError):
        open_any([new], blob, b"aad")


def test_lamport_clock():
    clock = LamportClock()
    assert clock.tick() == 1
    assert clock.update(10) == 11
    assert clock.tick() == 12
    assert clock.update(3) == 13


def test_seen_cache_dedups_and_bounds():
    cache = SeenCache(max_items=3, ttl=100)
    assert cache.check_and_add("a")
    assert not cache.check_and_add("a")
    assert cache.check_and_add("b")
    assert cache.check_and_add("c")
    assert cache.check_and_add("d")  # evicts "a"
    assert cache.check_and_add("a")


def test_rand_id_charset_and_uniqueness():
    import string

    alphabet = set(string.ascii_lowercase + string.digits)
    ids = {rand_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(i) == 12 and set(i) <= alphabet for i in ids)
