# Holler: Reconciled Task List

Assessment of the proposed recommendations (gossip routing, Lamport ordering, SRP, reconnection, TURN, AES-GCM, configurable signaling, typing/presence, metadata mitigation) against the current codebase, plus additional findings from a code review — reconciled into a single prioritized task list.

---

## Part 1: Verdicts on the original 9 recommendations

| # | Item | Verdict |
|---|------|---------|
| 1 | Gossip message routing | **Accept.** The sender-key design already lets any peer relay ciphertext without re-encryption, so flooding fits naturally. Two amendments: bound the `seen` set (time- or size-limited, not an unbounded set), and move `username`/`timestamp` inside the encrypted payload first — once messages arrive via relays, the current plaintext metadata is tamperable by any hop (see B7). |
| 2 | Lamport timestamps | **Accept as-is.** Only needed once gossip introduces multi-path delivery; sequence it after task 1. |
| 3 | SRP authentication | **Accept the goal; change the mechanism and the rationale.** Prefer **SPAKE2** (`python-spake2`) over SRP — simpler protocol, symmetric roles (no client/server assignment dance), better-maintained library than `srptools`. The original rationale (loud failure on wrong password) undersells it: today an **active MITM can offline-dictionary-attack the password**. DTLS certificate fingerprints travel through the untrusted signaling server inside the SDP, unverified out-of-band — a malicious signaling server can MITM the DTLS layer, complete the X25519 exchange with each victim, and then grind candidate passwords offline against the Fernet HMAC of the intercepted `holler.sender_key` message. A PAKE eliminates this class of attack entirely. The loud-failure UX alone is much cheaper to get via a key-confirmation round (task P0-2) and should land first. |
| 4 | Reconnection state machine | **Accept, widen scope.** The proposal covers DataChannel heartbeats but misses that the **signaling websocket** has no keepalive or reconnect either (B1, B2) — that half is more urgent because it likely breaks the app today. |
| 5 | TURN server configuration | **Accept as-is.** Straightforward `RTCIceServer` addition in `peer.py`; keep TURN-over-TCP disabled per the no-inbound-TCP constraint. |
| 6 | Fernet → AES-256-GCM | **Accept, but merge with an envelope redesign.** A bare cipher swap buys little. Do it as part of restructuring the message envelope: AES-256-GCM with the sender ID, timestamp, and message ID bound as AAD (or carried inside the plaintext), which also fixes spoofing and replay (B7). |
| 7 | Configurable signaling server | **Accept as-is.** Small change: promote the `PEERJS_WS_URL` constant (`peer.py:12`) to a CLI flag with `0.peerjs.com` as default. |
| 8 | Typing indicators and presence | **Presence is already implemented** — usernames are exchanged in the handshake, the UI shows an "Online:" list, and join/leave events render. Only typing indicators are new; lowest priority. |
| 9 | Signaling metadata exposure | **Fold into #7** (self-hosting is the practical mitigation) plus a README correction: the README's "no metadata" claim is false for the signaling phase. |

---

## Part 2: Additional findings (not in the original doc)

### Bugs

- **B1 — PeerJS keepalive is backwards** (`src/holler/peer.py:241-242`). The code only *replies* to server HEARTBEAT messages, but the PeerJS protocol expects the **client** to send heartbeats (~every 5 s); `peerjs-server` expires clients whose last ping is older than `alive_timeout` (default 60 s). Registrations — including the room ID alias — likely die about a minute in, making the room unjoinable. Verify against `0.peerjs.com`, then send periodic heartbeats from the client.

- **B2 — Silent signaling loss** (`src/holler/peer.py:251-252`). If the PeerJS websocket drops, `_signaling_loop` exits silently: no reconnect, no re-registration, and `_holding_room` stays stale in the client. The peer silently stops being reachable for new joiners.

- **B3 — Wrong password / failed handshake hangs forever**. A wrong password causes `Fernet.decrypt` to raise during the sender-key step; the exception is swallowed by `except Exception: pass` (`src/holler/client.py:235-236`) and a joiner blocks on `_first_peer_ready.wait()` (`src/holler/client.py:408`) with an infinite spinner. Protocol validation also uses `assert` (`src/holler/client.py:277,291,307,317`), which is stripped under `python -O`. Fix: explicit validation with typed errors, a key-confirmation round so a password mismatch fails loudly, and a join timeout with clear messages ("wrong password", "room not found").

- **B4 — Connection state leaks block retries**. If `connect_to` times out, its `_pending` entry is never removed (`src/holler/peer.py:113-116`) and the client's `_connecting` set is never cleared (`src/holler/client.py:218`), so re-dialing that peer is permanently blocked. Stale `RTCPeerConnection`s also accumulate in `_pcs` — never closed or removed on disconnect.

- **B5 — Offer glare**. Two peers dialing each other simultaneously (possible when two joiners appear in each other's rosters) each create an `RTCPeerConnection`; `_handle_offer` overwrites `_pcs[src]` (`src/holler/peer.py:186-187`) without closing the outbound one. Fix with a deterministic tie-break (e.g. lower peer ID acts as offerer; the other side abandons its own offer).

- **B6 — LEAVE/EXPIRE handled inconsistently** (`src/holler/peer.py:247-250`). These signaling messages pop `_channels` directly without firing `on_peer_disconnected`, so the client's per-peer session, roster, and room-holder logic don't learn of the departure until aiortc's own close detection fires — possibly never for silent drops. If the departed peer had the lowest ID, room takeover stalls. EXPIRE (offer undeliverable) also doesn't fail the pending dial fast; the joiner waits the full 30 s timeout.

- **B7 — Insider username spoofing; plaintext app-layer metadata**. `username` and `timestamp` ride in plaintext JSON outside the Fernet layer (`src/holler/client.py:370-378`), and the UI trusts the message's own `username` field (`src/holler/client.py:349`). Any group member can impersonate another; if DTLS were stripped, usernames/timestamps are visible despite the "double encryption" claim. Quick fix: display `state.username` from the authenticated handshake instead of the message field. Long-term: move metadata inside the AEAD envelope (merges with recommendation #6; prerequisite for gossip relaying).

- **B8 — Weak, non-cryptographic IDs** (`src/holler/peer.py:18-19`). `random.choices` (not CSPRNG) generates peer IDs, room IDs, and the PeerJS token, all 6 chars of base-36 (~31 bits). Room IDs are guessable/squattable on a public server (join-DoS: an attacker can register a guessed room ID or race the handoff). Use `secrets` and lengthen room IDs.

- **B9 — Password on argv** (`src/holler/cli.py:9`). The password is a positional CLI argument — visible in `ps` output and shell history. Prompt with `getpass` by default; keep the argument as an optional override (or support an env var).

- **B10 — Silent room-acquisition failure**. `_acquire_room` gives up after 5 attempts without reporting (`src/holler/client.py:158-165`); the creator still prints the Room ID even if it was never registered. On the join side, a bad room ID surfaces as a raw `TimeoutError` traceback out of `run_async`.

### Improvements

- **I1 — No tests or CI.** Zero tests; pre-commit runs only ruff and pyright. Add pytest with a fake transport to cover the handshake, key derivation, room-holder election, and disconnect handling; add a GitHub Actions workflow.
- **I2 — Terminal UX.** `console.clear()` re-renders clobber in-progress typing; the blocking `input()` executor thread lingers after quit until Enter is pressed; the `messages` list grows unbounded. Consider `prompt_toolkit` or Rich `Live` for a proper input line.
- **I3 — No sender-key rotation on membership change.** A departed member still holds everyone's sender keys. Channels close so they can't receive ciphertext, but rotating sender keys on leave is cheap post-compromise hardening. Optional.
- **I4 — README accuracy.** "No relay, no metadata" overstates — the signaling server sees IPs, peer IDs, and connection timing. Document the active-MITM dictionary-attack caveat (see verdict #3) until a PAKE lands.

---

## Part 3: Reconciled task list

### P0 — Correctness & security bugs (fix first)

| # | Task | Sources |
|---|------|---------|
| 1 | PeerJS client keepalive + signaling websocket reconnect with backoff and alias re-registration | B1, B2 |
| 2 | Loud handshake failure: replace asserts with validation, add key-confirmation round, join timeout with clear error messages | B3, B10, doc #3 (UX part) |
| 3 | Connection lifecycle cleanup: clear `_pending`/`_connecting` on failure, close stale `RTCPeerConnection`s, glare tie-break, consistent LEAVE/EXPIRE handling | B4, B5, B6 |
| 4 | Display names from authenticated handshake state, not message fields | B7 (quick fix) |
| 5 | `secrets`-based IDs with longer room IDs; `getpass` for the password | B8, B9 |

### P1 — Resilience

| # | Task | Sources |
|---|------|---------|
| 6 | Gossip/flood routing: message ID + origin + TTL envelope, bounded seen-set, re-broadcast on receive | doc #1 |
| 7 | Lamport timestamps with deterministic `(ts, origin)` sort for display | doc #2 |
| 8 | DataChannel heartbeats + per-peer reconnection state machine with exponential backoff | doc #4 |

### P2 — Security hardening

| # | Task | Sources |
|---|------|---------|
| 9 | PAKE authentication — SPAKE2 recommended over SRP; defeats offline dictionary attack by an active MITM | doc #3 (reframed) |
| 10 | Envelope redesign: AES-256-GCM with sender ID / timestamp / message ID bound via AAD; gives replay protection and unspoofable metadata | doc #6, B7 (long-term) |
| 11 | Optional TURN server CLI flags (`--turn`, `--turn-user`, `--turn-pass`); TURN-over-TCP disabled | doc #5 |

### P3 — Configurability & polish

| # | Task | Sources |
|---|------|---------|
| 12 | Configurable signaling server flag (`--signaling`), default `0.peerjs.com` | doc #7, doc #9 |
| 13 | Test suite (pytest, fake transport) + CI workflow | I1 |
| 14 | Terminal UX: non-clobbering input line, bounded message history, clean quit | I2 |
| 15 | README corrections: metadata claim, MITM caveat | I4 |
| 16 | Typing indicators; sender-key rotation on membership change — both optional | doc #8, I3 |

### Sequencing notes

- P0 items are independent of each other and of everything else — land them first and in any order.
- Task 10 (envelope redesign) is a prerequisite for making task 6 (gossip) tamper-proof; if gossip lands first, at minimum move `username`/`timestamp` inside the encrypted payload as part of it.
- Task 7 depends on task 6 (ordering only matters with multi-path delivery).
- Task 9 (PAKE) replaces the key-confirmation shim from task 2 when it lands; the HKDF password-mixing can stay as an extra layer.
