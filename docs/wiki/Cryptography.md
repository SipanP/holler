# Cryptography from First Principles

This page builds up every cryptographic idea holler uses, in order, assuming no prior
knowledge: symmetric encryption, integrity, authenticated encryption, key exchange
(with proof), the man-in-the-middle problem, the password-authenticated key exchange
that solves it (with proof), key derivation, forward secrecy, and group encryption.
It ends with [a table of every layer, every algorithm, and why](#511-every-layer-every-algorithm-and-why).

## 5.1 What we are defending against

Cryptography starts by naming the enemy. Holler's adversary is allowed to:

- read **every packet** on the network (your ISP, a coffee-shop Wi-Fi operator);
- **modify, drop, replay, or inject** packets (an "active" attacker);
- **run the signaling server** (we treat `0.peerjs.com` as potentially hostile);
- join the mesh and behave maliciously *if* they know the password.

The one thing the adversary does not have is the room password. Three classical goals,
against that adversary:

- **Confidentiality** — they can't read messages.
- **Integrity** — they can't alter messages without detection.
- **Authenticity** — they can't impersonate a group member.

A principle worth internalising immediately (**Kerckhoffs' principle**, 1883): a system
must be secure even if the attacker knows *everything about it except the keys*. All
of holler's algorithms are public and standard; every drop of secrecy lives in keys
and the password. Home-grown ciphers are how projects get broken — the craft is in
*composing* well-studied primitives correctly, which is what this page walks through.

## 5.2 Symmetric encryption: from XOR to AES

Start with the simplest cipher that is actually *perfect*. XOR (`⊕`) is bitwise
addition without carry; its key property is that it undoes itself:
`(m ⊕ k) ⊕ k = m ⊕ (k ⊕ k) = m ⊕ 0 = m`.

**One-time pad:** to encrypt message `m`, generate a random key `k` *as long as the
message* and send `c = m ⊕ k`. Claude Shannon proved (1949) this has *perfect
secrecy*: for any ciphertext `c` and any candidate message `m′` of the same length,
there exists exactly one key (`k′ = c ⊕ m′`) producing it — so `c` reveals literally
nothing about which message was sent. Two catches make it impractical: the key must be
as long as all traffic ever, and **reusing a pad is fatal** — from `c₁ = m₁ ⊕ k` and
`c₂ = m₂ ⊕ k` anyone computes `c₁ ⊕ c₂ = m₁ ⊕ m₂`, which is usually enough to recover
both messages. Remember this failure; it returns as the *nonce reuse* rule in §5.4.

Real systems therefore use a **block cipher**: a fixed, public, invertible scrambling
function selected by a short key. **AES** (the Advanced Encryption Standard, selected
by open international competition in 2001) maps a 16-byte block to a 16-byte block
under a 128/192/256-bit key, and after a quarter century of cryptanalysis the best
known attacks are marginal. The working assumption: without the key, AES's output is
indistinguishable from random.

A block cipher alone encrypts exactly 16 bytes. A **mode of operation** extends it to
arbitrary messages. The mode holler relies on is **CTR (counter) mode**: encrypt the
sequence `nonce‖0, nonce‖1, nonce‖2, …` with AES to produce a pseudorandom *keystream*,
and XOR it with the message — a one-time pad whose "pad" is generated from 32 bytes of
key. The one-time-pad rule carries over exactly: **the same key+nonce must never be
used twice**.

The older mode you'll meet in the wild, **CBC** (chain each block into the next),
works but has sharp edges: it needs padding to a block boundary, and the history of
"padding oracle" attacks (§5.4) is the history of CBC deployments.

## 5.3 Integrity: message authentication codes

Encryption alone does **not** stop tampering — this surprises everyone at first. In
CTR mode, flipping bit *i* of the ciphertext flips exactly bit *i* of the decrypted
plaintext (XOR is bitwise): an attacker who knows a message says `pay alice 10` can
flip the right bits to make it decrypt to `pay mALEX 10` *without any idea what the
key is*. Ciphertexts are malleable; secrecy and integrity are separate properties.

The tool for integrity is a **MAC** (message authentication code): a function
`MAC(key, message) → tag` such that, without the key, no attacker can produce a valid
tag for any new message — even after seeing tags for messages of their choosing
(*existential unforgeability*). The standard construction over a hash function is
**HMAC** (`HMAC(k, m) = H((k⊕opad) ‖ H((k⊕ipad) ‖ m))`), whose security reduces to
mild assumptions on the hash.

Holler uses HMAC-SHA256 directly in one place — the handshake's key-confirmation MAC
([§5.7](#57-pake-spake2-the-algorithm-that-fixes-passwords)) — and everywhere else
gets MAC-like integrity bundled inside AES-GCM, next.

One subtlety worth knowing because it generalises: when *checking* a MAC, comparing
byte-by-byte with early exit (`==`) leaks *how many leading bytes were right* through
timing, which lets an attacker forge a tag byte at a time. Comparisons of secrets must
be constant-time — hence `hmac.compare_digest` in `crypto.py`.

## 5.4 AEAD: AES-256-GCM and associated data

Combining a cipher and a MAC yourself invites ordering mistakes (encrypt-then-MAC vs
MAC-then-encrypt — only the former is generically safe). Modern practice merges them
into one primitive: **AEAD**, *authenticated encryption with associated data*. Holler
uses **AES-256-GCM** for every envelope. GCM =

- **CTR mode** (§5.2) for confidentiality, plus
- **GHASH**, a polynomial-evaluation MAC over the ciphertext *and* over any
  **associated data (AAD)** — bytes that are *authenticated but not encrypted*.

Decryption verifies the tag *before* releasing a single byte of plaintext; a tampered
ciphertext, a wrong key, or mismatched AAD all yield one indistinguishable error.

**AAD is the feature holler leans on hardest.** A gossip envelope
([Distributed Algorithms §6.1](Distributed-Algorithms#61-gossip-surviving-dead-links-with-proof))
travels through *other people's clients*, which must read its routing metadata
(message ID, origin, Lamport timestamp, kind) to forward it. That metadata can't be
encrypted — but it must not be forgeable, or a relay could re-attribute a message to
another user or shuffle timestamps. So `client.py` binds exactly that metadata as AAD:

```python
aad = f"holler.gossip:{msg_id}:{origin}:{lamport}:{kind}"
blob = seal(sender_key, plaintext, aad)      # crypto.py
```

If any relay alters any of those fields, every recipient's tag check fails and the
message is dropped. One line of AAD replaces an entire signature scheme *within the
group's trust model* (a member's identity is vouched for by possession of their sender
key, which only the password-authenticated handshake distributes).

**The nonce rule, quantified.** GCM nonces are 96 bits and holler draws them at
random per message (`crypto.seal`). Reusing a key+nonce pair is catastrophic (it XORs
keystreams like a reused one-time pad *and* leaks the MAC key — Joux's "forbidden
attack"), so it's worth checking the arithmetic: by the birthday bound, after `q`
messages under one key the collision probability is ≈ `q²/2⁹⁷`. At an absurd million
messages per second for a year (`q ≈ 2⁴⁵`), that's ≈ `2⁻⁷` — and holler additionally
rotates sender keys on every membership change (§5.10), resetting `q`. Safe with
orders of magnitude to spare.

**Why AES-256-GCM here, and not…**

- *Fernet* (what holler v1 used): AES-128-CBC + HMAC — a sound encrypt-then-MAC
  design, but it has **no AAD**, uses 128-bit keys, and CBC's padding invites the
  classic **padding oracle** failure mode (Vaudenay 2002: if an attacker can merely
  *distinguish* "bad padding" from "bad data" errors, CBC decrypts completely — the
  bug class behind POODLE and Lucky13). The AAD gap alone forced the change: the
  gossip envelope design is impossible with Fernet.
- *ChaCha20-Poly1305*: the equally good modern alternative; faster on CPUs without
  AES hardware. Either would do; AES-GCM was chosen for ubiquity (it's also what the
  DTLS layer negotiates, keeping the stack's assumptions uniform).

## 5.5 Key exchange: Diffie–Hellman, with proof

Everything so far assumed a shared key. The magic trick at the heart of all modern
secure channels is establishing one **over a wire the adversary is reading**.

**Diffie–Hellman (1976), in plain integers.** Fix public parameters: a large prime
`p` and a generator `g`. ("Generator" means powers of `g` mod `p` cycle through the
whole group — every element is `gᵏ` for some `k`.)

1. Alice picks a random secret `a`, sends **A = gᵃ mod p**.
2. Bob picks a random secret `b`, sends **B = gᵇ mod p**.
3. Alice computes `Bᵃ`; Bob computes `Aᵇ`.

**Correctness (a real proof, two lines):** exponentiation composes multiplicatively —
`(gᵇ)ᵃ = g^{ba} = g^{ab} = (gᵃ)ᵇ (mod p)`, by writing out the product of `ab` copies
of `g` and reordering (multiplication mod p is commutative and associative). ∎
Both parties hold the same value `K = g^{ab}` having only ever transmitted `gᵃ` and
`gᵇ`.

**Security (why the eavesdropper is stuck):** recovering `a` from `gᵃ mod p` is the
**discrete logarithm problem** — for well-chosen 2048-bit-plus groups, no known
algorithm runs in feasible time. What security actually rests on is the (slightly
stronger, unproven but 50-years-unbroken) **computational Diffie–Hellman assumption**:
given `g, gᵃ, gᵇ` it is infeasible to compute `g^{ab}`. Unlike the correctness proof,
this is an *assumption* — all of public-key cryptography rests on such assumptions,
which is why parameter choices follow decades of cryptanalysis rather than taste.

**Elliptic curves, and why X25519.** The same algebra works in any group where
"exponentiation" is easy but "logarithm" is hard. Points on an **elliptic curve** form
such a group, and their discrete-log problem is *much* harder per bit: 256-bit curve
keys ≈ 3072-bit classic DH keys, with far cheaper computation. Holler uses **X25519**
(RFC 7748), the DH function over Curve25519, for reasons that go beyond size:

- **Misuse-resistant by design** — every 32-byte string is a valid public key; there
  are no parameter or point-validation mistakes to make (a real attack class against
  older NIST-curve implementations: invalid-curve and twist attacks).
- **Constant-time by construction** (the Montgomery ladder), closing the timing
  side channel of §5.3 at the key-exchange layer too.
- Independently designed with published rationale (Bernstein 2006), and the de facto
  standard in Signal, WireGuard, TLS 1.3, and SSH.

In holler, each peer generates a **fresh X25519 key pair per connection** — that
"ephemeral" choice is what buys forward secrecy (§5.9).

## 5.6 The man-in-the-middle problem, and why passwords are hard

DH has a hole the maths cannot fix: it agrees a key with *whoever is on the other
end*. An active attacker **M** sitting between Alice and Bob (say, a malicious
signaling server — the exact position `0.peerjs.com` occupies) simply runs *two* DH
exchanges — one with each victim — and re-encrypts traffic in the middle, reading
everything. Neither victim can tell: they each completed a perfectly valid exchange.

The web solves this with certificates; holler's DTLS layer can't (its certificate
fingerprints travel *through the untrusted signaling server* — a MITM swaps them; see
[Networking §4.8](NAT-Traversal-and-Networking#48-the-webrtc-stack-sdp-dtls-sctp)). A
serverless group of friends has exactly one shared secret to authenticate with: **the
room password**. And passwords are dangerous, because they're *guessable*, so the
design question becomes: *can an attacker test password guesses, and at what cost?*

Here is the cautionary tale, and it's holler's own v1 design. It derived the pairwise
key as `key = HKDF(dh_secret ‖ password)` and immediately used it to encrypt a
message with an authenticated cipher. Consider the MITM above: M runs a DH exchange
with Alice, so **M knows `dh_secret`** (it's M's own exchange!). Alice then sends
`Enc(HKDF(dh_secret ‖ password), …)`. Now M walks away and, entirely on its own
hardware, for each candidate password `pw′` computes `HKDF(dh_secret ‖ pw′)` and
tries to decrypt — the AEAD tag check ([§5.4](#54-aead-aes-256-gcm-and-associated-data))
says definitively whether the guess was right. That is an **offline dictionary
attack**: a modern GPU rig tests billions of guesses per second against the roughly
2⁴⁰-guess space of human-chosen passwords. One intercepted handshake ≈ password
recovered overnight.

The fix requires a genuinely clever primitive.

## 5.7 PAKE: SPAKE2, the algorithm that fixes passwords

A **PAKE** (password-authenticated key exchange) achieves something that sounds
impossible: two parties agree on a strong key using a weak password, such that an
attacker — even an *active* MITM — gets **at most one online password guess per
protocol run**, and a transcript is useless for offline grinding. Holler uses
**SPAKE2** (Abdalla–Pointcheval 2005; RFC 9382), in its symmetric variant, implemented
by the [`python-spake2`](https://github.com/warner/python-spake2) library over the
Ed25519 group.

**The construction.** Work in a prime-order group with generator `g` (as in §5.5,
but on an elliptic curve). The protocol fixes one extra public group element `S`
whose discrete log nobody knows (a "nothing-up-my-sleeve" constant). Derive from the
password a scalar `w = H(password)`. Then, with `x, y` random:

```
Alice → Bob:   X = gˣ · Sʷ         (her DH share, *blinded* by the password)
Bob → Alice:   Y = gʸ · Sʷ

Alice:  K = (Y / Sʷ)ˣ  = (gʸ)ˣ = g^{xy}
Bob:    K = (X / Sʷ)ʸ  = (gˣ)ʸ = g^{xy}
session key = H(transcript ‖ w ‖ K)
```

**Correctness proof:** `Y / Sʷ = gʸ·Sʷ·S⁻ʷ = gʸ`, so Alice computes `(gʸ)ˣ = g^{xy}`;
symmetrically Bob gets `g^{xy}` — the blinding factors cancel *iff both used the same
`w`*, i.e. the same password. ∎ (With different passwords nothing breaks visibly —
the two sides just end up with different keys, which is why an explicit confirmation
step follows.)

**Why a transcript is useless offline (the beautiful part):** consider an
eavesdropper holding `X = gˣ·Sʷ` and testing a candidate password `w′`. Unblinding
gives `X/S^{w′} = g^{x}·S^{w-w′}` — *some* group element. But since `x` is uniformly
random and `g` generates the whole group, `gˣ` is a uniformly random element, so `X`
itself is uniformly distributed **whatever `w` is**. Every candidate password is
perfectly consistent with the observed transcript; there is nothing to check a guess
against. To *test* `w′` you must compute `g^{xy}` from the unblinded shares — which is
exactly the computational Diffie–Hellman problem (§5.5) unless you personally chose
`x` or `y`. And that is the online-only loophole, precisely as intended: an active
attacker can pick their own `y`, guess `w′`, run the protocol once, and see if the
confirmation MAC verifies — **one guess, per run, visible to the victim as a failed
join**. Guessing a decent password now takes billions of *interactive sessions with a
human-noticeable failure each*, instead of a quiet weekend of GPU time.

**Key confirmation, and a subtle reflection trap.** SPAKE2's `finish()` always
outputs *a* key; to turn "wrong password" into a loud, immediate error, both sides
exchange `HMAC(confirm_key, own_peer_id)` and verify the peer's
(`crypto.PairwiseCrypto.confirmation`). MAC'ing over each side's *own ID* makes the
two directions' proofs different values — otherwise an attacker could simply **echo
your own proof back at you** ("reflection") and pass verification knowing nothing.
Wrong password ⇒ different `K` ⇒ MAC mismatch ⇒ `AuthenticationError` within one
round trip. This is the mechanism behind holler failing fast and loudly on a typo'd
password.

**Belt and braces:** holler still runs a plain ephemeral X25519 exchange alongside
and mixes both into the session key, `HKDF(x25519_secret ‖ spake2_key)` — if a flaw
were ever found in either primitive, the other still stands alone.

**Why SPAKE2 and not the alternatives?**

- *SRP* (the older, widely deployed PAKE): designed for client↔server with a stored
  verifier; requires assigning asymmetric roles (awkward between equal peers), has
  legacy structural warts (it needs special "safe prime" groups and resists analysis
  in modern frameworks), and its maintained Python implementations lag.
  SPAKE2's symmetric variant needs no role negotiation at all — both peers run
  byte-identical code, which matters in a mesh where connections race in both
  directions.
- *OPAQUE* (the state of the art for client↔server logins): solves the problem of the
  *server* storing something crackable — irrelevant here, where nobody stores anything.
- *Doing nothing* (v1's HKDF mixing): broken by §5.6.

## 5.8 HKDF: turning secrets into keys

A recurring chore: you hold some high-entropy-but-oddly-shaped secret (a DH point, a
concatenation of two secrets) and need uniform, independent keys for specific jobs.
Using raw secrets directly, or one key for two purposes, is how related-key bugs
happen. **HKDF** (RFC 5869) is the standard answer, built entirely from HMAC in two
steps: **extract** (concentrate the input's entropy into one uniform key) then
**expand** (stretch it into any number of output keys, each labelled by an `info`
string). Distinct labels yield computationally independent keys.

Every derivation in holler goes through `crypto._hkdf` with a distinct label —
`"holler-pairwise"` for the session key, `"holler-confirm"` for the confirmation-MAC
key — plus versioned AAD-style labels on every envelope (`"holler.sec:…"`,
`"holler.rekey:…"`, `"holler.gossip:…"`). This *domain separation* guarantees that a
ciphertext or MAC produced in one context can never be replayed as valid in another.

## 5.9 Forward secrecy

Question worth asking of any encrypted system: *if my long-term secret leaks tomorrow,
what happens to yesterday's traffic?* If the answer is "decryptable", an adversary can
record ciphertext today and wait.

Holler's only long-term secret is the password, and the answer is "nothing happens":
session keys derive from **ephemeral** X25519/SPAKE2 values (`x`, `y`) that are
generated per connection, live only in RAM, and are destroyed on disconnect. A future
password thief holds transcripts of the form `gˣ·Sʷ` and AEAD ciphertext; without the
long-gone `x` or `y`, computing the session key is still the CDH problem (§5.5) —
knowing `w` doesn't help. That property is **forward secrecy**. (Its mirror,
*post-compromise security* — healing after a device compromise — is what sender-key
rotation partially provides, next.)

## 5.10 Group encryption: sender keys and rotation

Pairwise keys secure two-party links; a *group* needs a broadcast story. Three
standard designs, with their trade-offs:

1. **Encrypt per recipient** — N−1 encryptions and N−1 sends per message. Robust but
   quadratic traffic in the mesh; wasteful when a message is already being flooded.
2. **One shared group key** — one encryption per message, but *any* member can forge
   messages *as* any other member (everyone holds the only key), and every membership
   change forces a group-wide renegotiation.
3. **Sender keys** — each member generates their own random 32-byte AES key at
   session start and hands it to every other member over the authenticated pairwise
   channels. Messages are encrypted **once** with the author's own key and flooded;
   everyone decrypts with their stored copy of the *author's* key.

Holler uses (3), the same pattern as Signal group chats. It keeps the flood-friendly
"encrypt once" property of a group key while restoring authenticity: successfully
decrypting an envelope with *Bob's* sender key (tag check and all, §5.4) proves it
was sealed by someone holding Bob's key — which the handshake only ever gave to Bob's
authenticated peers, and which the AAD binds to Bob's ID. A member cannot forge
another member's messages.

**Rotation:** whenever anyone leaves (gracefully or by timeout), every remaining
member generates a fresh sender key and re-distributes it over the pairwise channels
(`client._rotate_sender_key`, message type `holler.rekey`). A departed member's key
material therefore goes stale immediately — even if they somehow kept receiving
ciphertext, they could not read anything sent after their departure. Recipients keep
exactly one previous key per sender (`crypto.open_any` tries newest-first) so
messages in flight across a rotation aren't lost. New joiners, symmetrically, receive
only current keys and can read nothing from before they joined.

## 5.11 Every layer, every algorithm, and why

The complete inventory, bottom to top — note how each layer covers the one below's
known gap:

| Layer | Algorithm | What it protects | Why this one / known gap it leaves |
|---|---|---|---|
| Wire transport | **DTLS 1.2** (inside WebRTC, negotiated by aiortc) | everything on the wire from passive snooping | mandatory in WebRTC; free. **Gap:** its self-signed cert fingerprints ride through the untrusted signaling server → MITM-able there ([Networking §4.8](NAT-Traversal-and-Networking#48-the-webrtc-stack-sdp-dtls-sctp)) |
| Peer authentication | **SPAKE2** (Ed25519 group) + ephemeral **X25519**, mixed via HKDF | proves password knowledge; kills offline dictionary attacks by the MITM above | symmetric roles, modern analysis, maintained library; X25519 kept as independent second leg (§5.7) |
| Loud failure | **HMAC-SHA256** key confirmation over own peer ID | wrong password fails fast; blocks reflection | one HMAC each way; simplest possible mutual proof (§5.7) |
| Key derivation | **HKDF-SHA256** with per-purpose labels | independent keys per job; domain separation | the standard; nothing else is defensible (§5.8) |
| Handshake payloads & rekeys | **AES-256-GCM** under the pairwise key, purpose-labelled AAD | sender keys, usernames, roster in transit | AEAD needed anyway; one primitive everywhere (§5.4) |
| Group messages | **AES-256-GCM** under per-author **sender keys**; envelope metadata as AAD | confidentiality + unforgeable authorship + tamper-proof routing metadata through relays | encrypt-once for flooding; AAD is what makes gossip safe — Fernet's lack of AAD forced its retirement (§5.4, §5.10) |
| Membership change | **sender-key rotation** | leavers can't read the future | cheap post-compromise hygiene (§5.10) |
| Identifiers | `secrets`-based 62-bit room IDs, random 96-bit nonces, random per-message IDs | unguessable rooms; nonce safety; replay detection | CSPRNG only — Python's `random` is predictable from its outputs |

---

> **Go deeper:** Aumasson, *Serious Cryptography* (the right first book);
> Boneh & Shoup, *A Graduate Course in Applied Cryptography* (free, rigorous — the
> proofs here in full); the [Cryptopals challenges](https://cryptopals.com/) (you
> implement the padding-oracle and nonce-reuse attacks yourself — the fastest way to
> believe them); RFCs 7748 (X25519), 5869 (HKDF), 9382 (SPAKE2); NIST SP 800-38D (GCM).

*Next: [Distributed Algorithms](Distributed-Algorithms) · Up: [Home](Home)*
