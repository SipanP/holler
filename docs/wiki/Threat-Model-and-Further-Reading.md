# Threat Model and Further Reading

## What holler does *not* protect against

No security document is complete without the list of things the system does *not*
protect against. Holler's:

- **The signaling server sees metadata.** Never content or key material (SPAKE2
  guarantees that even against a malicious server —
  [Cryptography §5.7](Cryptography#57-pake-spake2-the-algorithm-that-fixes-passwords))
  — but it does see IP addresses, peer IDs, room IDs, and who connects to whom, for
  the seconds each handshake takes. Mitigation: self-host with `--signaling`
  (one line: `npx peer --port 9000`).
- **Members are trusted.** Anyone with the password is inside the cryptographic
  boundary: they read everything and could spam or flood. There is no moderation
  layer. Choose passwords and friends accordingly.
- **Weak passwords fall to online guessing.** SPAKE2 reduces attackers to one guess
  per interactive attempt — visible, slow, and noisy — but a password in the top-100
  list survives even that only briefly.
- **Traffic analysis.** An observer of your network link can see *that* you're
  chatting, packet timing, and rough volume, even though every byte is encrypted.
  Resisting this (padding, cover traffic, onion routing) is out of scope.
- **No message history, by design.** RAM only; a peer that was offline missed what it
  missed. The seen-cache dedups replays but nothing re-delivers the past.
- **Symmetric-NAT pairs need TURN**
  ([Networking §4.6](NAT-Traversal-and-Networking#46-turn-the-relay-of-last-resort)),
  which you must supply yourself.
- **Endpoint compromise is game over,** as in every E2E system: malware reading your
  terminal reads your chat.

## Where to learn more

### Networking / NAT traversal

- Ford, Srisuresh, Kegel — [*Peer-to-Peer Communication Across Network Address Translators*](https://bford.info/pub/net/p2pnat/) (2005): the hole-punching paper.
- Tailscale — [*How NAT traversal works*](https://tailscale.com/blog/how-nat-traversal-works): the best modern explainer, goes far beyond this guide.
- [*WebRTC for the Curious*](https://webrtcforthecurious.com/): free book on the full WebRTC stack.
- RFC 8445 (ICE), RFC 8489 (STUN), RFC 8656 (TURN), RFC 8831 (WebRTC data channels).

### Cryptography

- Jean-Philippe Aumasson — *Serious Cryptography* (2nd ed., 2024): the right first book.
- Dan Boneh, Victor Shoup — [*A Graduate Course in Applied Cryptography*](https://toc.cryptobook.us/): free, rigorous, contains the real versions of every proof sketched in this guide.
- [Cryptopals](https://cryptopals.com/): hands-on attack implementation; sets 2–4 cover the CBC/CTR/GCM failure modes from the [Cryptography](Cryptography) page.
- RFC 7748 (X25519), RFC 5869 (HKDF), RFC 9382 (SPAKE2), NIST SP 800-38D (GCM).
- Abdalla, Pointcheval — *Simple Password-Based Encrypted Key Exchange Protocols* (CT-RSA 2005): SPAKE2's original analysis.
- RFC 9420 (MLS): how sender-key-style group crypto scales to enterprise messengers.

### Distributed systems

- Leslie Lamport — [*Time, Clocks, and the Ordering of Events in a Distributed System*](https://lamport.azurewebsites.net/pubs/time-clocks.pdf) (CACM 1978).
- Demers et al. — *Epidemic Algorithms for Replicated Database Maintenance* (PODC 1987).
- Martin Kleppmann — *Designing Data-Intensive Applications*, ch. 8–9; and his free [distributed systems lecture notes](https://www.cl.cam.ac.uk/teaching/2122/ConcDisSys/dist-sys-notes.pdf).
- Fischer, Lynch, Paterson — *Impossibility of Distributed Consensus with One Faulty Process* (1985), for why the failure-detection section hedges.

### This codebase

- `tests/test_client.py` is executable documentation: every behaviour on the
  [Distributed Algorithms](Distributed-Algorithms) page (relay around a dead link,
  dedup, ordering, rotation, takeover, reconnection) has a test driving real clients
  over the in-memory transport in `tests/fakes.py`.
- `tests/e2e_smoke.py` runs the real thing against a live signaling server.

---

*Up: [Home](Home)*
