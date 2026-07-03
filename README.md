# Holler

**Encrypted peer-to-peer group terminal chat — no servers in the message path, no logs, no trace.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

---

Holler connects any number of terminals in a fully encrypted group chat using WebRTC. A PeerJS signaling server brokers the initial handshakes — after that, it's completely out of the picture. Messages travel peer-to-peer only.

## How it works

Peers form a full mesh: every participant holds a direct DataChannel to every other participant. When a new peer joins, they receive a roster of existing members and establish connections to each one independently.

- **Full mesh + gossip routing** — every peer connects directly to every other peer, and every message is flooded through the mesh with a unique ID and TTL. If a direct link between two peers dies, their messages still arrive via any surviving path. Duplicates are dropped by a bounded seen-cache.
- **Consistent ordering** — messages carry Lamport timestamps and are ordered by `(timestamp, origin)`, so every peer's log converges to the same order regardless of arrival order.
- **Self-healing links** — every channel is heartbeated. A link that goes quiet is torn down and re-dialed with exponential backoff (the lower peer ID redials, the higher one waits, so the two sides never collide). A peer that stays unreachable is announced as gone.
- **Persistent room ID** — a stable room ID is separate from any peer's ephemeral connection ID. The peer with the lowest ID holds it; if that peer leaves, the next-lowest re-registers it automatically. The room stays joinable as long as one peer is alive.
- **Password authentication (PAKE)** — every pairwise connection runs a SPAKE2 exchange. Both sides prove they know the shared password without transmitting it or anything derived from it that could be attacked offline. A wrong password fails loudly at key confirmation.
- **Double encryption** — DTLS secures each DataChannel at the transport layer; AES-256-GCM secures messages at the application layer with a key the signaling server never sees.
- **Forward secrecy** — each pairwise connection uses ephemeral X25519 and SPAKE2 values, destroyed on disconnect. Past sessions can't be decrypted even if the password later leaks.
- **Sender keys with rotation** — each peer encrypts outbound messages once with its own random sender key, distributed over the pairwise channels. When anyone leaves the group, every remaining peer rotates its sender key, so a departed member can't read anything sent after they left.
- **RAM only** — keys and messages exist only in memory. Nothing touches disk. Everything is gone on disconnect.

## Security

### Key exchange and authentication

For each pairwise connection:

```
1. Both peers exchange SPAKE2 messages and ephemeral X25519 public keys.

2. Both derive the pairwise key:
   pairwise_key = HKDF(x25519_secret ‖ spake2_key)

   SPAKE2 is a password-authenticated key exchange: an attacker who
   intercepts (or actively MITMs) the entire exchange learns nothing
   they can test candidate passwords against, even offline.

3. Both sides exchange key-confirmation MACs. If the passwords differ,
   this fails immediately and loudly — no silent garbled messages.

4. Each peer sends its sender key over the confirmed pairwise channel,
   sealed with AES-256-GCM.

5. Session ends → ephemeral values destroyed → keys gone forever.
```

### Message envelopes

Every chat message is sealed with AES-256-GCM under the origin's sender key. The envelope metadata — message ID, origin peer ID, Lamport timestamp, message kind — is bound as *associated data*, so relaying peers can route messages but cannot alter, re-attribute, or replay them (replays are dropped by the message-ID cache). Usernames and timestamps live inside the encrypted payload, and sender identity comes from the authenticated handshake, never from a spoofable field.

### Double encryption

1. **DTLS (transport layer)** — WebRTC encrypts each DataChannel automatically.
2. **AES-256-GCM (application layer)** — before a message hits the DataChannel, holler seals it with keys the signaling path never touches.

If DTLS were broken or terminated by a middlebox, the attacker still sees only AEAD ciphertext, with no usable metadata inside.

Inspired by [CMD-CHAT](https://github.com/emilycodestar/cmd-chat)

### What the signaling server sees

The signaling server never sees message content or key material — SPAKE2 makes even an actively malicious signaling server unable to recover the password or session keys. It *does* see connection metadata: peer IDs, IP addresses, and who connects to which room, for the seconds each handshake takes. If that matters for your threat model, self-host the signaling server (`--signaling`); the PeerJS server is a one-line deploy (`npx peer --port 9000`).

## Installation

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync
```

## Usage

**Alice** starts a session and shares the room ID (the password is prompted, so it never lands in shell history or `ps` output):

```bash
uv run holler alice
# Room password: ********
# Room ID: xk92mq3v7bt1
```

**Bob and Carol** join using that room ID:

```bash
uv run holler bob --join xk92mq3v7bt1
uv run holler carol --join xk92mq3v7bt1
```

All peers must use the same password — it authenticates every pairwise key exchange and is never sent over the network. Additional peers can join at any time. The room ID stays valid as long as at least one peer is connected.

Inside the chat: type to send, `/who` lists who's online, `/quit` (or `q`) exits. A typing indicator appears in the bottom toolbar when someone else is composing.

### Options

```
holler USERNAME [PASSWORD] [--join ROOM_ID]
       [--signaling URL]      custom PeerJS-compatible signaling server
       [--stun URL]           custom STUN server
       [--turn URL --turn-user U --turn-pass P]
                              TURN relay for symmetric-NAT traversal (UDP only)
```

Without a TURN server, peers behind symmetric NATs (some corporate networks and mobile carriers) may be unable to connect directly; any [coturn](https://github.com/coturn/coturn) instance on a cheap VPS works.

## Contributing

```bash
uv sync --group dev
uv run pre-commit install
uv run pytest
```

Ruff and Pyright run on every commit; CI runs the full test suite on Python 3.9 and 3.13. The test suite drives real clients over an in-memory transport, covering the handshake, gossip relay, ordering, key rotation, reconnection, and room takeover.

## License

MIT
