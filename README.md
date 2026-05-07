# Holler

**Encrypted peer-to-peer group terminal chat — no servers, no logs, no trace.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

---

Holler connects any number of terminals in a fully encrypted group chat using WebRTC. The PeerJS signaling server brokers the initial handshakes — after that, it's completely out of the picture. No relay, no metadata, nothing written to disk.

## How it works

Peers form a full mesh: every participant holds a direct DataChannel to every other participant. When a new peer joins, they receive a roster of existing members and establish connections to each one independently.

- **Full mesh** — every peer connects directly to every other peer. No relay, no hub, no single point of failure.
- **Persistent room ID** — a stable room ID is separate from any peer's ephemeral connection ID. One peer holds it at a time; if that peer leaves, the remaining peer with the lowest ID re-registers it automatically. The room stays joinable as long as one peer is alive.
- **Double encryption** — DTLS secures each DataChannel at the transport layer; Fernet (AES-128-CBC + HMAC) secures messages at the application layer. A compromised signaling server sees only SDP blobs.
- **Forward secrecy** — each pairwise connection uses an ephemeral X25519 keypair. Peers derive a shared secret via ECDH and authenticate it with the password using `HKDF(ecdh_secret ‖ password)`. Past sessions can't be decrypted even if the password is later compromised.
- **Sender keys** — each peer generates a random symmetric key for their outbound messages and distributes it to all others over the pairwise-encrypted channels. Messages are encrypted once and broadcast to the group.
- **RAM only** — keys and messages exist only in memory. Nothing touches disk. Everything is gone on disconnect.

## Security

### Double encryption

Messages pass through two independent encryption layers:

1. **DTLS (transport layer)** — WebRTC encrypts each DataChannel automatically. It protects the wire.
2. **Fernet/AES (application layer)** — before a message hits the DataChannel, Holler encrypts it with a key your code controls. Plaintext never exists at the DTLS layer.

If DTLS were broken or terminated by a middlebox (e.g. a corporate proxy doing TLS inspection), the attacker still sees Fernet ciphertext they can't read.

Inspired by [CMD-CHAT](https://github.com/emilycodestar/cmd-chat)

### Forward secrecy and key exchange

Forward secrecy answers: _"If my password leaks tomorrow, can someone decrypt today's traffic?"_ Without it, yes. With it, no.

For each pairwise connection:

```
1. Both peers generate ephemeral X25519 keypairs and exchange public keys

2. Both compute the same ECDH shared secret:
   alice_priv × bob_pub  ==  bob_priv × alice_pub  (math guarantee)

3. Pairwise key = HKDF(ecdh_secret ‖ password)
   The password is mixed into the KDF — it never leaves your machine.
   An attacker who intercepts the public key exchange still can't derive
   the pairwise key without the password.

4. Each peer encrypts their sender key with the pairwise key and sends it.
   Both peers now hold the other's sender key.

5. Session ends → ephemeral keypairs destroyed → keys gone forever.
```

### Sender keys

Each peer generates a random 32-byte sender key at session start. After the pairwise key exchange, they distribute it to every other peer, encrypted with the pairwise key. Outbound messages are encrypted once with the sender key and broadcast to all. Recipients decrypt using the stored sender key for that peer.

This means an attacker must compromise the pairwise channel (requiring the ephemeral ECDH secret _and_ the password) to recover a sender key — the same bar as breaking the session encryption directly.

## Installation

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync
```

## Usage

**Alice** starts a session and shares the room ID:

```bash
uv run holler alice mysecret
# Room ID: xk92m
```

**Bob and Carol** join using that room ID:

```bash
uv run holler bob mysecret --join xk92m
uv run holler carol mysecret --join xk92m
```

All peers must use the same password — it authenticates the key exchange and is never sent over the network. Additional peers can join at any time. The room ID stays valid as long as at least one peer is connected; if the current holder leaves, another peer takes over the room ID automatically.

## Contributing

```bash
uv sync --group dev
uv run pre-commit install
```

Ruff and Pyright run automatically on every commit.

## License

MIT
