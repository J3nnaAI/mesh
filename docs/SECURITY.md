# Security model & threat model — J3nna Mesh

This document describes the security architecture of the J3nna Mesh: how trust is
rooted, how peers authorize one another offline, how authorization is revoked, and
what the design does **not** protect against. It is written to be honest: where a
control is partial, that is stated plainly. Under-claiming is preferred to
over-claiming.

Companion documents:

- [`./AUDIT-LOGGING.md`](./AUDIT-LOGGING.md) — what each component logs and how to audit it.
- [`./OPERATIONS.md`](./OPERATIONS.md) — deployment and operational runbook. *(Forward reference; see the
  operator checklist at the end of this document for the security-relevant subset.)*

All primitives are Go standard library only. Cryptography in use:

| Purpose | Primitive |
|---|---|
| Node & authority identity, all signatures | ed25519 |
| Secret-at-rest encryption (vault) | Pluggable Cipher — export-grade DES-56 + HMAC-SHA256 default (one fresh nonce per entry; handle bound), swappable to AES-256-GCM via WithCipher (CRYPTO.md) |
| Vault passphrase key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output |
| Webhook payload authentication (signal-bridge) | HMAC-SHA256 |
| Argument binding for capability calls | SHA-256 |

There is no bespoke cryptography. Where a fact below depends on an exact value
(grant lifetime, CRL poll interval, freshness window), the value is taken directly
from source and named.

---

## 1. Trust model — root, not hub

The control-plane **console** is the **root of trust**, not a routing hub.

- The console holds an ed25519 **root keypair**, persisted to a `0600` file
  (`CONSOLE_ROOT_KEY`, default `console-root.key`). It is generated on first run if
  absent.
- The console **originates** authorization (enroll → approve → issue a signed grant)
  and **revokes** it (publish a signed CRL). That is its entire security role.
- The console is **never on the hot path** of a peer-to-peer interaction. Two peers
  that have already enrolled call each other directly and verify each other
  **offline** against one value: the **authority root public key**, served once at
  `GET /authority` and pre-seeded into each peer at enrollment.

The single trust anchor every peer must carry is the **root public key**. Everything
else (grants, the CRL) is signed by the root and therefore verifiable without
contacting the console.

**Testable invariant:** during a normal peer-to-peer interaction (discovery,
tools/call, room post) no peer makes any call to the console. The only background
console traffic is the periodic CRL fetch and the grant renewal that rides the same tick
(§4, `agentkit.KeepFresh`), neither of which is on the request path; both tolerate the
console being briefly offline.

---

## 2. Identity

Each peer is a `jip.Node` with a stable cryptographic identity:

- An **ed25519 keypair** plus a v4 UUID node id, generated on first run and persisted
  to a `0600` identity file (`IdentityFile`). The private key never leaves the process
  except into that operator-controlled file.
- The id is **stable across restarts** because the keypair is persisted. Stability is
  required: a grant and any allow-list entry bind to a specific node id, so an id that
  changed on restart could not be authorized in advance.
- A peer announces itself in a **signed presence record** (`PresenceRecord`): a
  canonical, length-prefixed, language-neutral byte encoding of its payload, signed
  with its private key. Verification recomputes the same bytes and checks the
  signature against the public key embedded in the payload. A presence record is the
  *only* trust object on the wire; the UDP source address and any out-of-band metadata
  are never trusted.
- **Key pinning:** the registry binds `(node id → public key)` on first verified
  sight. Any later record claiming that id but signed by a different key is rejected
  (`pinned key mismatch`). This stops a UUID-collision impersonation even before
  authorization is considered.

---

## 3. Authorized discovery — the admit gate

Authorization is **opt-in** and is enabled by configuring `AuthorityRoot` on a peer.

- **With `AuthorityRoot` set** (production posture): the peer installs an **admit
  gate** that every incoming presence record must pass before it can enter the
  registry. A peer that does not pass is simply not recorded — nothing in the mesh will
  try to talk to it. It is invisible, not merely unprivileged.
- **With `AuthorityRoot` unset** (development posture): discovery is **open** — any
  verifiable presence record is admitted. Do not run a production mesh without an
  authority root.

A peer carries its console-signed **grant** inside its signed presence. The grant id is
covered by the presence signature, so a grant cannot be lifted onto a different
presence record. The admit gate performs **all** of the following checks, entirely
offline (source: `jip.New`, the `reg.admit` closure):

1. **Protocol-major compatibility** — `CompatibleMajor(presence.ProtocolMajor)`; a peer
   on an incompatible wire major is rejected (§6).
2. **Grant present** — a presence with no grant is rejected.
3. **Subject binding** — `grant.Subject == presence.ID`.
4. **Pubkey binding** — `grant.PublicKey == presence.PublicKey` (the grant is pinned to
   the exact key the presence is signed with).
5. **Not revoked** — `grant.ID` is not in this peer's current CRL view.
6. **Authority signature + expiry** — `VerifyGrant(grant, root, now)`: the grant's
   ed25519 signature verifies against the root public key, and `now <= grant.NotAfter`.

Only a record passing all six enters the registry. There is no console round-trip in
this path.

---

## 4. Grants and their lifetime

A grant (`jip.Grant`) is an authority-signed authorization binding a subject (node id) to
a pinned public key, a tier, optional scopes, and an expiry. It is signed over a
canonical, domain-separated, length-prefixed encoding (`GrantSigningBytes`, domain tag
`J3nna-mesh-grant/1`) so issuer and verifier agree byte-for-byte.

**Grant lifetime is short and fixed.** `GrantTTL` is a **compile-time constant of 5
minutes** (`jip.GrantTTL = 5 * time.Minute`). The console sets
`NotAfter = IssuedAt + GrantTTL`, and the admit gate enforces `NotAfter` on every merge.
The short TTL is the worst-case revocation backstop; long-running peers stay authorized
not by living longer but by **renewing** (below).

### Grant renewal — staying authorized without re-approval

A long-running peer keeps its grant alive by **renewing** before it expires, and it does
so **without the console ever being on the hot path** and **without a fresh operator
approval**. The mechanism (source: `jip/grant.go`, `console/authority.go RenewGrant`,
`console/main.go /renew`, `agentkit/crl.go KeepFresh`):

- The peer POSTs its **current grant** plus a node-key signature to `POST /renew`
  (`jip.RenewalRequest{grant, issued_at, signature}`). The signature is over a canonical,
  domain-separated encoding (`RenewSigningBytes`, domain tag `J3nna-mesh-renew/1`) and
  **proves possession of the exact node key the grant is pinned to** (`VerifyRenewal`).
- `/renew` is **cryptographically self-authenticating**: it requires no operator action
  and no `mayManage`. The presented grant is itself the proof of prior approval. The
  authority (`RenewGrant`) re-issues only if that grant **verifies against the root,
  is unexpired, and is not in the CRL**.
- The renewed grant keeps the **same grant id** — the stable revocation handle — and only
  advances the validity window (same subject, pubkey, tier, scopes), re-signed by the
  root. **Revocation therefore dominates renewal:** revoking that id (§5) permanently
  kills the whole renewal chain; an expired or revoked grant cannot be renewed and the
  peer must re-enroll.
- Renewal rides the **same periodic background tick as the CRL refresh**
  (`agentkit.KeepFresh`): on each tick the peer refreshes the CRL and, once its grant is
  **past half its lifetime (~2.5 min)**, renews it. The console is touched only on this
  background tick — **never on a peer-to-peer call** (root-not-hub preserved). The
  `room-agent`, `signal-bridge`, and `samples/joiner` all run `KeepFresh`. `RefreshCRL`
  remains for a peer given a long-lived static grant out of band that never renews.

> **Honest residual.** While the console is reachable, a renewing peer stays in
> discovery indefinitely. Renewal fires past the grant's half-life with a half-life
> (~2.5 min) of 30-second-tick retry margin before the grant would actually expire, so it
> absorbs a momentary console blip. But an **unplanned console outage longer than roughly
> half the TTL near a renewal still eventually partitions** the authorized mesh — the
> grant expires and the peer falls out of discovery until the console returns and it
> renews (or re-enrolls). This is the consciously accepted availability tradeoff of the
> short TTL; it **fails closed** (a peer disappears rather than over-staying its
> authorization). The design's answer for *planned* downtime — a signed, time-bounded
> **maintenance-mode auto-extend** — is **designed but not yet implemented** in this
> release.

The grant id is the **revocation handle** (§5).

---

## 5. Revocation

Revocation is signature-based and propagates without trusting any intermediary.

- The console revokes a grant by adding its id to the **CRL** and persisting it
  (`0600`, `CONSOLE_CRL`). `GET /crl` returns a **signed CRL** (`jip.SignedCRL`): the
  revoked set plus an ed25519 signature over a canonical encoding (`CRLSigningBytes`,
  domain tag `J3nna-mesh-crl/1`).
- Each authorized peer refreshes the CRL in the background (the bundled agents via
  `agentkit.KeepFresh`, which also renews — §4; a static-grant peer via
  `agentkit.RefreshCRL`): fetch the CRL → **verify its signature against the root** →
  apply it. A CRL that fails verification is **never applied** — a forged or unsigned CRL
  cannot strip authorizations.
- Applying a CRL calls `Node.SetRevoked`, which both (a) updates the admit gate so future
  presences from a revoked grant are rejected, and (b) **immediately evicts** any
  already-admitted peer whose grant id is now revoked (`evictRevoked`). Eviction does not
  wait for TTL expiry.

**Revocation window, with real numbers.** The bundled agents poll the CRL every **30
seconds** (`KeepFresh(..., 30*time.Second)`). So a revoked peer is evicted **within one
refresh interval (~30 s)** under normal operation. The grant TTL is the worst-case
backstop: even if the CRL never reaches a peer (console down, network partition), the
revoked grant still expires at `NotAfter`. A failed CRL fetch or verify is **skipped
silently** — the last good CRL plus the TTL continue to protect; revocation is delayed,
never bypassed.

---

## 6. Semantic versioning as a security control

The wire protocol carries a major version (`jip.ProtocolMajor = 1`). A peer interoperates
**only** with peers on the same major (`CompatibleMajor`: same major only; major `0` /
unknown is rejected when authorization is enforced). The admit gate enforces this
**before** any other grant check, and it **fails closed**: a peer speaking an
incompatible (e.g. future breaking) protocol is treated as un-admittable rather than
optimistically engaged. Module releases use path-prefixed semver tags; a breaking
protocol change requires a major bump, which a deployed mesh will reject until upgraded.

---

## 7. Capability authorization — CallProof

Discovery makes a peer *visible*; it does not by itself authorize *actions*. A tool
exposed over MCP (`tools/call`) may be marked **restricted**. Calling a restricted tool
requires a **CallProof** (`jip.CallProof`):

- A fresh ed25519 signature by the **caller's** node key over a canonical,
  domain-separated encoding (`signedBytes`, domain tag `JIP-call/0.2`) binding:
  **caller node id + tool name + a SHA-256 hash of the exact arguments + a timestamp.**
- The server (source: `authorizeCall`) accepts only if: a proof is present; it names
  this tool; the args-hash **matches the actual arguments**; the caller id is
  **allow-listed**; the caller is a known mesh member; the signature verifies against
  the caller's **pinned** public key; and the timestamp is within a **±30-second**
  freshness window (`callProofMaxSkew`).

This binds the proof to one tool and one exact argument payload — **a captured proof
cannot be replayed with different arguments.** See the residual on the freshness window
in §11: there is no nonce/once-tracking, so the *identical* call is replayable within the
±30 s window.

Non-restricted tools (read/observation, e.g. `signal.poll`) require no proof. The
guidance is: any tool that **acts or spends** must be registered `restricted=true`.

---

## 8. TLS posture

Peers may serve HTTPS. The transport policy (`loopbackAwareTLSDial`, mirrored in
`agentkit.InsecureLoopbackTransport`) is precise:

- TLS verification is skipped **only for loopback addresses** (`127.0.0.1`, `::1`) — the
  case where a self-signed dev/loopback certificate is expected.
- **Every off-host address is verified normally**, with the hostname pinned as
  `ServerName`.

This is structural: "insecure TLS" can never silently extend to a cross-host peer, so it
cannot become a remote MITM hole. The peer-to-peer authentication that actually matters
does not depend on TLS at all — it is the ed25519 presence/grant/CallProof chain, which
holds regardless of transport.

---

## 9. Secrets at rest — the vault

The `vault` module (`github.com/J3nnaAI/mesh/vault`) is the encrypted secret store used
by the console (token→identity map) and the signal-bridge (webhook HMAC secrets).

- **Encryption:** pluggable Cipher (export-grade DES-56-CTR + HMAC-SHA256 by default; AES-256-GCM via WithCipher), one fresh random nonce per entry, with the entry **handle
  as additional authenticated data** (so a ciphertext cannot be silently relabelled to
  another handle). Stored in a single `0600` JSON file.
- **Key sources** (resolved from `<PREFIX>_*`, in order): `<PREFIX>_KEY` (base64 of
  exactly 32 bytes) → `<PREFIX>_KEYFILE` (a file holding 32 bytes raw/base64/hex) →
  `<PREFIX>_PASSPHRASE` (PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt
  persisted with the vault).
- **Fail-closed:** with no key source the vault opens **locked** — it serves no values
  and rejects writes (`ErrLocked`) rather than running unprotected.
- **List/read separation:** `List` returns handles, descriptions, and timestamps only —
  **never values.** `Get` returns plaintext only at the internal injection point and is
  documented as never to be logged or returned to a model.

**At-rest boundary — named honestly.** When the key is supplied by an env var or a
keyfile, the vault protects the secret *values* against: the vault file being committed to
git, copied into a backup, captured in logs, or exfiltrated **on its own**. It does
**not** protect against a host compromise where the attacker can also read the env var,
the keyfile, or process memory. There is **no OS keyring integration**; key material
lives in the environment or in `0600` files owned by the same uid as the process.

---

## 10. Cryptographic agility & post-quantum posture

**Status, stated plainly: the mesh is NOT yet quantum-resistant — its signatures use ed25519, which is
classical (pre-quantum). What the mesh IS, by design, is _crypto-agile_ and _PQC-ready_: a post-quantum
signature scheme can be adopted as a non-breaking upgrade, and the one piece that genuinely needs to be
quantum-safe today — the encrypted vault — already is.** This section explains exactly where the quantum
exposure is, where it is not, and why this posture is the cryptographically honest one rather than a
deferral.

### What a quantum computer threatens

A cryptographically-relevant quantum computer (CRQC) runs two algorithms that matter here:

- **Shor's algorithm** efficiently breaks _asymmetric_ (public-key) cryptography — RSA, and finite-field
  and elliptic-curve discrete logs. **ed25519 (Ed25519 / Curve25519) is in this class.** A CRQC could in
  principle recover an ed25519 private key from its public key and forge signatures. This is the headline
  post-quantum risk, and it is the same risk that retires RSA and ECDSA.
- **Grover's algorithm** speeds up brute-force search of _symmetric_ keys and hash preimages, but only
  **quadratically** — it effectively halves the security level. It does **not** break symmetric crypto; it
  only asks for larger parameters.

### Where the mesh is exposed: signatures (asymmetric)

Every trust decision in the mesh rests on an **ed25519 signature** (§2, §3, §4, §7):

- **node identity keys** sign presence records, capability call proofs (`CallProof`), and grant-renewal
  requests;
- the **authority root key** signs grants and the CRL.

These are the quantum-exposed surface. A CRQC able to forge ed25519 could forge presence, mint grants, or
sign capability calls.

### Where the mesh is NOT exposed: the vault (symmetric)

The encrypted secret store (§9) uses a **pluggable Cipher** — export-grade DES-56 + HMAC-SHA256 by default, AES-256-GCM via WithCipher — with keys derived by
**PBKDF2-HMAC-SHA-256**. This is _entirely symmetric / hash-based — there is no public-key component for
Shor to attack._ The only quantum lever is Grover, which against AES-256 leaves ~128-bit effective
security (and against SHA-256 preimages, ~128-bit) — both far beyond feasible. **The vault therefore needs
no change to be quantum-resistant; AES-256 is the standard post-quantum-safe symmetric choice** — which is
precisely why the NIST post-quantum project replaced only the public-key primitives, not AES or SHA-2. A
harvest-now-decrypt-later attack against vault files captured today still faces full AES-256.

### Why signatures are lower-urgency than encryption — the asymmetry that justifies this posture

The industry deployed post-quantum _key exchange_ (hybrid X25519 + ML-KEM in TLS / browsers) **before**
post-quantum _signatures_, for a sound reason that applies directly here:

- **Encryption / key exchange has a "harvest-now, decrypt-later" threat.** Ciphertext captured _today_ can
  be stored and decrypted _years later_ once a CRQC exists. Confidentiality must therefore be made
  quantum-safe **proactively**, ahead of the machine. (The mesh's confidential-at-rest surface is the
  vault — and it is already symmetric-256, above.)
- **Signatures have no equivalent retroactive threat.** A signature only needs to remain unforgeable
  **until it is verified and expires** — there is no value in forging one after the fact. And the mesh's
  signatures are deliberately **short-lived**: grants live **5 minutes** (§4), call proofs have a
  **±30-second** freshness window (§7), presence is re-signed every gossip tick. The only realistic
  signature threat is **real-time forgery by a CRQC** — a machine that does not exist today and, when it
  does, will be met by the migration below long before any such window opens.

So for a signature-based system with short-lived credentials, **crypto-agility plus a documented migration
is the industry-aligned, honest posture — not a "good enough for now" shortcut.**

### What was built now: algorithm agility, before the wire freeze

The decision that _had_ to be made before 1.0 is not "ed25519 or PQC" but "**is the 1.0 wire format able
to add PQC without a breaking change.**" If it cannot, adding PQC after release becomes a breaking wire
change that — under the major-compatibility enforcement the mesh ships as a feature (§6) — would
**partition the network**. So, while the wire format is still unfrozen:

- **Every signed structure carries a signature-algorithm tag** (`alg`): presence payloads, `Grant`,
  `SignedCRL`, `CallProof`, and renewal requests.
- **The tag is covered by the canonical signing bytes.** It is part of what is signed, so it **cannot be
  stripped or downgraded** — flipping the tag changes the bytes and invalidates the signature (enforced by
  test).
- **Verifiers reject any unknown algorithm fail-closed.** Today the only value is `ed25519` (an empty tag
  normalizes to it, for forward-compatibility); a v1 peer presented with a tag it does not understand
  refuses it rather than guessing — the same fail-closed discipline as the authorized-discovery admit gate
  (§3).

The consequence: a post-quantum algorithm can be **added without a protocol-major bump** — the agility
primitive (a covered, fail-closed algorithm tag) is in place, so introducing one is a minor change rather
than a flag-day. To be precise about what exists today: this is fail-closed algorithm **identification**,
not negotiation — a current (v1) peer will *reject* a future hybrid/PQC peer's signatures (unknown tag),
not transparently interoperate with it. Cross-version interop is a property of the migration plan below
(e.g. a hybrid peer presenting an ed25519-verifiable form to v1 peers), not something the tag alone
delivers. Nothing is released yet, so this simply _is_ the 1.0 format; and no dependency was added (the
stdlib-only / zero-supply-chain property is intact).

### Post-quantum: the upgrade path

The planned next step is a **hybrid** signature: ed25519 **and** a NIST-standardized PQC signature, both
required to verify. Hybrid is the conservative choice — no weaker than ed25519 today, quantum-safe the
moment the PQC half holds, with no single-algorithm risk during the transition. Candidate schemes:

- **ML-DSA (FIPS 204, "Dilithium")** — lattice-based; the likely default. The trade-off to design around:
  ML-DSA signatures are large (~2.4 KB for ML-DSA-44) versus ed25519's 64 bytes, which interacts with the
  UDP-multicast presence beacon (≈1500-byte MTU). The heavy signature must be carried deliberately (e.g.
  out-of-band of the beacon) — exactly why this is a considered follow-up, not a pre-release bolt-on.
- **SLH-DSA (FIPS 205, "SPHINCS+")** — hash-based, conservative assumptions, larger signatures; a
  candidate where signature size is acceptable and assumption-minimalism is valued.
- **ML-KEM (FIPS 203, "Kyber")** — key encapsulation, in the Go standard library today (`crypto/mlkem`);
  relevant only if a confidential _transport_ beyond TLS is ever added — not for signatures.

The honest claim the code and docs make, and no more: **crypto-agile and PQC-ready; not yet
quantum-resistant; post-quantum signatures are a planned, non-breaking hybrid upgrade; the symmetric vault
is already quantum-resistant.**

---

## 11. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Impersonate a peer / hijack a node id | Signed presence; `(id→pubkey)` pinned on first sight; grant binds id↔pubkey | Pre-pinning, a first-seen attacker could claim an unused id; authorization (grant) still blocks engagement |
| Unauthorized peer joins / is engaged | Admit gate: grant signature vs root, subject/pubkey binding, not-in-CRL, compatible major — all offline | None for *engagement*; an unauthorized peer can still *receive* multicast packets (it just cannot be admitted) |
| Forged or self-issued grant | Grant must verify against the authority **root** signature; root private key never leaves the console | Theft of the root private key (see checklist §13) compromises issuance — protect it |
| Stolen/leaked grant reused after compromise | CRL revocation, verified against root, evicts within ~30 s; TTL expiry (5 min) as backstop; renewal keeps the **same id**, so revoking it kills the whole renewal chain | Up-to-~30 s window before eviction; if the CRL never propagates, up to the 5-min TTL |
| Forged CRL stripping authorizations | CRL signature verified against root before apply; unsigned/forged CRL never applied | A withheld (not forged) CRL delays revocation to the TTL backstop |
| Replay a captured renewal request to extend a grant | `VerifyRenewal` enforces a ±2-min freshness window (`RenewMaxSkew`) and node-key possession; `RenewGrant` re-checks root signature + expiry + CRL | A replay only re-issues a grant for a key the attacker **cannot sign presence with** — useless without the node key; revoking the id ends renewal regardless |
| Replay a captured capability call with new arguments | CallProof binds tool + SHA-256 of exact arguments | Identical call replayable within the ±30 s freshness window (no nonce/once-tracking) |
| Call a privileged tool without authority | Restricted tools require a signed, allow-listed, fresh CallProof | Operator must remember to mark acting/spending tools `restricted=true` |
| Cross-host TLS MITM | Off-host TLS always verified (ServerName-pinned); skip-verify is loopback-only | Loopback traffic is unverified by design (same host) |
| Secret-file exfiltration / backup / log leak | Vault pluggable cipher (export-grade DES-56 default; AES-256-GCM via WithCipher) with key held separately (env/keyfile) | Host compromise reading the key source defeats it; no OS keyring |
| Spoofed inbound webhook raising a false signal | `/hook/<id>` requires a matching HMAC-SHA256 over the body; fail-closed (401 on mismatch) | Secret theft (same at-rest boundary as the vault); failures are **not currently logged** (see AUDIT-LOGGING.md) |
| Run-time downgrade to an incompatible protocol | `CompatibleMajor` rejects incompatible majors before any other check (fail-closed) | None at the protocol-major granularity |
| Downgrade the signature algorithm (e.g. strip a future PQC tag to force ed25519) | The `alg` tag is covered by the signing bytes; changing it invalidates the signature, and unknown algorithms are rejected fail-closed (§10) | None for downgrade; the residual is that ed25519 itself is not yet post-quantum (next row) |
| Future quantum forgery of ed25519 signatures | Crypto-agility makes the move to a PQC signature (ML-DSA) a non-breaking upgrade; short-lived signatures (5-min grants, ±30 s proofs) limit the forgery window; the vault is already symmetric/PQ-safe (§10) | **NOT yet quantum-resistant** — ed25519 is classical; real PQC signatures are a planned hybrid upgrade (§10). No CRQC exists today |

---

## 12. Residual risks / out of scope

Stated plainly so operators can decide what compensating controls they need:

- **Same-uid key/token theft.** The node identity key, the console root key, the CRL,
  and the vault keyfile are `0600` files owned by the running uid. There is **no OS
  keyring** and no hardware-backed key storage. An attacker who already runs code as the
  same uid (or root) can read them. File permissions, not isolation, are the boundary.
- **Inference / content leakage is out of scope.** The mesh authenticates and authorizes
  *who may talk to whom and call what*. It does not classify, redact, or constrain the
  *content* an authorized peer chooses to send or what a model infers from it.
- **The revocation window is real.** Normal eviction is bounded by the CRL refresh
  interval (~30 s in the bundled agents); the absolute backstop is the 5-minute grant
  TTL. There is no instantaneous global revocation.
- **Grant renewal is automated, but bounded by console reachability** (see §4). The
  bundled agents renew on a background tick (`agentkit.KeepFresh`) and stay authorized
  indefinitely while the console is reachable. What remains a residual is an **unplanned
  console outage longer than ~half the TTL near a renewal**, which still eventually
  partitions the authorized mesh until the console returns. This is an availability gap,
  not a confidentiality one — it fails closed (a peer disappears rather than over-staying
  its authorization). A signed, time-bounded **maintenance-mode auto-extend** for planned
  downtime is designed but not yet implemented.
- **Multicast flood DoS is accepted.** Anyone on the LAN can flood the discovery group
  (`239.42.42.42:9999`) with junk; unverifiable frames are dropped before touching the
  registry, so the worst case is wasted CPU on signature verification. This is accepted
  because **authorization gates communication, not packet receipt** — a flood cannot get
  an unauthorized peer engaged, only burn cycles. The gossip and MCP HTTP endpoints cap
  bodies at 1 MiB; rate-limiting beyond that is left to the host/operator.
- **CallProof freshness, not single-use.** The ±30 s window plus args-binding stops
  swapped-argument replay but not identical-call replay inside the window. Tools whose
  effect must be exactly-once should enforce idempotency themselves.
- **No automatic key rotation.** Rotating the root key, node identities, or vault keys is
  an operator action (see checklist).
- **Not yet post-quantum (signatures).** Signatures use classical ed25519; the mesh is
  crypto-agile and PQC-ready but not yet quantum-resistant. The threat is real-time
  forgery by a quantum computer that does not exist today, and the migration to a PQC
  signature is non-breaking by design. The symmetric vault is already quantum-resistant.
  Full reasoning and roadmap in §10.

---

## 13. Operator security checklist

1. **Set a strong vault key.** Provide `CONSOLE_VAULT_KEY` / `_KEYFILE` / `_PASSPHRASE`
   (and the equivalent `SIGNAL_VAULT_*` for the signal-bridge). A locked vault disables
   user/webhook management; an unprotected one is not an option — there is no plaintext
   fallback. Prefer a 32-byte keyfile or env key over a passphrase for non-interactive
   hosts.
2. **Protect the authority root key.** `console-root.key` (or `CONSOLE_ROOT_KEY`) is the
   single anchor of the whole mesh. Keep it `0600`, off backups that aren't themselves
   protected, and never in version control. Its theft means an attacker can mint valid
   grants and CRLs.
3. **Bind management surfaces to loopback.** The console (`CONSOLE_ADDR`, default
   `127.0.0.1:8455`) and the signal-bridge management HTTP (`SIGNAL_HTTP`, default
   `127.0.0.1:8484`) gate privileged actions on loopback **or** a bearer token. Keep them
   on loopback (or a trusted private interface fronted by your own auth) — remote
   management depends entirely on bearer-token secrecy.
4. **Treat issued credentials as shown-once.** Bearer tokens and webhook HMAC secrets are
   returned exactly once at creation. Store them securely; the console keeps only the
   mapping/fingerprint, never the full secret.
5. **Grant renewal is automatic via `agentkit.KeepFresh`** (§4) — the bundled agents
   renew before expiry while the console is reachable, so a long-running peer stays
   authorized without re-approval. Keep the console reachable on its CRL/renew interval;
   an extended unplanned outage near a renewal will partition the mesh until it returns.
   Revoking a grant id stops its renewal chain too.
6. **Rotate.** Periodically rotate bearer tokens (`DELETE /users/<token>`), webhook
   secrets, and — on suspected compromise — the authority root key (which invalidates all
   existing grants and forces re-enrollment).
7. **Monitor the CRL and the audit signals.** Confirm `GET /crl` is reachable from peers
   on the expected interval, and watch for the events called out in
   [`./AUDIT-LOGGING.md`](./AUDIT-LOGGING.md) — repeated rejected admits, inbound-hook
   signature failures, and unexpected grant revocations.

---

*Apache-2.0. This document describes the mesh infrastructure only; agents and personas
built on top of it have their own security considerations out of scope here.*
