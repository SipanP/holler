# Quick Start

Holler needs Python 3.10+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
git clone https://github.com/SipanP/holler
cd holler
uv sync
```

**Start a room** (you'll be prompted for a password — it never appears in your shell
history or `ps` output):

```bash
uv run holler alice
# Room password: ********
# Room ID: xk92mq3v7bt1
```

**Join from other terminals/machines**, using the same password:

```bash
uv run holler bob --join xk92mq3v7bt1
uv run holler carol --join xk92mq3v7bt1
```

Inside the chat: type and press Enter to send, `/who` lists who is online, `/quit`
(or `q`) exits. A toolbar at the bottom shows who is typing.

## Options

| Flag | Purpose |
|------|---------|
| `--join ROOM_ID` / `-j` | Join an existing room instead of creating one |
| `--signaling URL` | Use your own PeerJS-compatible signaling server — see [Networking §4.9](NAT-Traversal-and-Networking#49-signaling-peerjs-and-how-holler-implements-all-of-this) |
| `--stun URL` | Override the STUN server (default: Google's public STUN) |
| `--turn URL --turn-user U --turn-pass P` | Add a TURN relay for networks where hole punching fails — see [Networking §4.6](NAT-Traversal-and-Networking#46-turn-the-relay-of-last-resort) |

## For development

```bash
uv sync --group dev
uv run pytest        # 22 unit + integration tests, no network needed
uv run ruff check .
uv run pyright
uv run python tests/e2e_smoke.py   # live test against a real signaling server
```

CI runs lint, format, types, and the test suite on Python 3.10 and 3.13, plus a
non-blocking live smoke test against the public signaling server.

---

*Next: [Codebase Tour](Codebase-Tour) · Up: [Home](Home)*
