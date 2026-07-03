"""Cryptographic building blocks: PAKE handshake, AEAD envelopes, logical clocks.

All symmetric encryption is AES-256-GCM with a random 96-bit nonce prepended to
the ciphertext. Every encryption call binds associated data (AAD) so envelope
metadata — sender identity, message ID, logical timestamp — cannot be altered
in transit without failing authentication.
"""

import hashlib
import hmac
import secrets
import string
import time
from collections import OrderedDict
from typing import Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from spake2 import SPAKE2_Symmetric

from holler.errors import AuthenticationError

NONCE_LEN = 12
KEY_LEN = 32

_ID_ALPHABET = string.ascii_lowercase + string.digits


def rand_id(n: int = 12) -> str:
    """Returns a cryptographically random lowercase alphanumeric ID.

    Args:
        n: Length in characters. The default of 12 gives ~62 bits of entropy,
            enough to make room IDs unguessable on a public signaling server.
    """
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(n))


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=b"holler-v3", info=info).derive(
        secret
    )


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypts with AES-256-GCM, returning ``nonce ‖ ciphertext``.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.
        aad: Associated data authenticated (but not encrypted) with the message.
    """
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Decrypts a ``seal`` blob with a single key.

    Raises:
        AuthenticationError: If the blob is malformed or authentication fails.
    """
    if len(blob) <= NONCE_LEN:
        raise AuthenticationError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise AuthenticationError("decryption failed") from exc


def open_any(keys: Iterable[bytes], blob: bytes, aad: bytes) -> bytes:
    """Tries each key in order until one decrypts the blob.

    Used for sender keys, where a recent rotation means the previous key may
    still be in flight.

    Raises:
        AuthenticationError: If no key authenticates the blob.
    """
    for key in keys:
        try:
            return open_sealed(key, blob, aad)
        except AuthenticationError:
            continue
    raise AuthenticationError("no key could decrypt the message")


class PairwiseHandshake:
    """One side of the SPAKE2 + X25519 pairwise key agreement.

    SPAKE2 (a PAKE) proves both sides know the shared password without ever
    revealing it — an active man-in-the-middle learns nothing they can grind
    offline against a password list. The X25519 exchange is mixed in as an
    independent second source of ephemeral secrecy.

    A password mismatch does not fail here — SPAKE2 simply yields different
    keys on each side. It fails loudly at the confirmation step
    (:meth:`PairwiseCrypto.verify_confirmation`).
    """

    def __init__(self, password: bytes):
        self._spake = SPAKE2_Symmetric(password, idSymmetric=b"holler-v3")
        self._x25519 = X25519PrivateKey.generate()
        self._spake_msg: Optional[bytes] = None

    def outbound(self) -> "tuple[bytes, bytes]":
        """Returns ``(spake2_message, x25519_public_key)`` to send to the peer."""
        if self._spake_msg is None:
            self._spake_msg = bytes(self._spake.start())
        msg: bytes = self._spake_msg
        return msg, self._x25519.public_key().public_bytes_raw()

    def finish(self, spake_msg: bytes, x25519_pub: bytes) -> "PairwiseCrypto":
        """Completes the exchange with the peer's public values.

        Raises:
            AuthenticationError: If the peer's SPAKE2 message is malformed or
                reflected (a corrupted/hostile handshake, not a wrong password).
        """
        try:
            spake_key = self._spake.finish(spake_msg)
        except Exception as exc:
            raise AuthenticationError(f"PAKE exchange failed: {exc}") from exc
        ecdh = self._x25519.exchange(X25519PublicKey.from_public_bytes(x25519_pub))
        return PairwiseCrypto(_hkdf(ecdh + spake_key, b"holler-pairwise"))


class PairwiseCrypto:
    """Authenticated encryption + key confirmation for one peer pair."""

    def __init__(self, key: bytes):
        self._key = key
        self._confirm_key = _hkdf(key, b"holler-confirm")

    def confirmation(self, own_peer_id: str) -> bytes:
        """Returns the key-confirmation MAC proving we derived the same key.

        The MAC covers the sender's own peer ID, so the two directions produce
        different values (preventing reflection) and the claimed identity is
        bound to password knowledge.
        """
        return hmac.new(self._confirm_key, own_peer_id.encode(), hashlib.sha256).digest()

    def verify_confirmation(self, their_peer_id: str, mac: bytes) -> bool:
        """Checks the peer's confirmation MAC. False almost always means wrong password."""
        expected = hmac.new(self._confirm_key, their_peer_id.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, mac)

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        return seal(self._key, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes) -> bytes:
        return open_sealed(self._key, blob, aad)


class LamportClock:
    """Logical clock giving all peers a consistent total order over messages."""

    def __init__(self):
        self.time = 0

    def tick(self) -> int:
        """Advances the clock for a send event and returns the new value."""
        self.time += 1
        return self.time

    def update(self, received: int) -> int:
        """Merges a received timestamp and returns the new local value."""
        self.time = max(self.time, received) + 1
        return self.time


class SeenCache:
    """Bounded set of recently seen gossip message IDs.

    Entries expire after ``ttl`` seconds and the cache never exceeds
    ``max_items``, so long sessions cannot leak memory.
    """

    def __init__(self, max_items: int = 8192, ttl: float = 600.0):
        self._max = max_items
        self._ttl = ttl
        self._entries: "OrderedDict[str, float]" = OrderedDict()

    def check_and_add(self, msg_id: str) -> bool:
        """Records ``msg_id``; returns True if it was new, False if seen before."""
        now = time.monotonic()
        while self._entries:
            oldest_id, ts = next(iter(self._entries.items()))
            if now - ts > self._ttl or len(self._entries) >= self._max:
                del self._entries[oldest_id]
            else:
                break
        if msg_id in self._entries:
            return False
        self._entries[msg_id] = now
        return True
