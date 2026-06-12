# Why J3nna Mesh

> **The interop protocols answer *how* agents talk. J3nna Mesh answers *who's allowed to.***
> An authorization-first agent mesh where a peer is invisible until a console-signed grant
> lets it in — verified peer-to-peer, offline, with no broker on the data path.

---

## Part of a larger purpose

AI is becoming the substrate beneath modern life — and right now, access to it is
*concentrating*, not spreading. The organizations that can afford to wire AI into their work
pull further ahead; everyone else is left on the outside. Every transformative technology
starts this way. The question is always the same: does someone build the bridge that turns
concentrated power into **distributed capability** — or does the gap harden?

J3nna Technologies exists to build that bridge: to make AI a basic material available to
everyone, woven in so it simply works — for every idea, and for every person, however they
interact with it. Not a luxury reserved for those with engineering teams and budgets. A
substrate that's seamless, transparent, and *owned by the people who use it.*

**J3nna Mesh is one piece of that — the foundation underneath.** A substrate stays open only
if the network it runs on does too. As AI goes from one assistant each to *many* cooperating
agents, the layer where those agents find and trust each other is being quietly handed to a
handful of clouds. J3nna Mesh keeps that layer **decentralized and owned by you** — so the
power stays distributed, not captured. The rest of the vision rides on infrastructure like
this being in everyone's hands, not rented back to them.

This document is about that foundation. The honest, technical case for it follows.

---

## The 60-second version

We're going from one AI assistant each to *dozens* of specialized agents — on our laptops,
phones, edge devices, and servers. They'll need to find each other and safely use each
other's abilities. Today you get two options, both bad:

- **Centralized:** wire everything through a cloud broker that sits in the middle of every
  interaction — it sees your data, owns the directory, decides who may talk, and becomes your
  single point of control and failure.
- **Raw peer-to-peer:** no broker in the middle, but no governance either — anyone can join,
  nothing stops an impostor or a poisoned agent, and there's no way to pull a compromised one
  off the network.

**J3nna Mesh is the missing third option: decentralized *and* governed.** Agents discover and
call each other directly and verify each other with cryptography — no broker on the wire.
Trust originates from a root *you* run (a small console), but that root is never in the path:
agents carry signed, **offline-verifiable** grants and check each other peer-to-peer. A peer
is invisible to the mesh until you've granted it in; revoke it and it's evicted everywhere in
seconds; every sensitive call is cryptographically proven, so it can't be forged or replayed.
**You own the trust. You don't rent the hub.**

---

## The story

**The shift already underway.** For two years the unit of AI was one model in one chat
window. That's ending. The frontier now is *agents* — software that acts, remembers, uses
tools, and pursues goals — and it won't be one agent, it'll be many. Soon "how many agents do
you run?" will be as ordinary as "how many apps do you have?"

**The question nobody's asking.** The industry is racing to let agents *talk*: Anthropic's MCP
gave them a shared language for tools; Google's A2A gave them a way to introduce themselves.
Real progress — but that's the *syntax* of collaboration. It leaves the harder question
untouched: **when your agents meet to work together, whose ground do they meet on, and who
decides who's allowed in the room?** Today's unspoken answer is "a cloud you rent." We're
quietly rebuilding the centralized internet — a few companies in the middle of everything —
one agent connection at a time. That's the opposite of distributed capability.

**The gap is real, not rhetorical.** This isn't a hunch. libp2p — the most mature P2P stack —
[states in its own docs](https://docs.libp2p.io/concepts/security/security-considerations/)
that it "does not provide an authorization framework out of the box" and "intentionally leaves
authorization to the application." MCP and A2A don't *mandate* identity verification at all: a
[scan of public MCP servers found 1,800+ exposed without authentication](https://knostic.ai/blog/mapping-mcp-servers-study),
and A2A's own "agent cards" carry **self-declared** identity the spec doesn't require anyone to
verify. A [2026 survey of agent-identity protocols](https://arxiv.org/abs/2603.24775) found
that *no implemented protocol* yet combines verifiable delegation, offline verification, and
provenance the way a real authorization layer needs to. The "who's allowed" layer is missing.

**What we built.** J3nna Mesh fills exactly that gap. Your agents discover each other and
verify each other peer-to-peer; a root you own originates trust but never touches traffic; an
agent is invisible until granted; revocation propagates in seconds via a signed CRL; restricted
tool calls require an arguments-bound signed proof. And it's **MCP-compatible** — it speaks the
language everyone's adopting — so the thing it adds isn't *another* way for agents to talk, it's
the **authorization and topology** layer underneath, for when you don't want a cloud in the
middle.

**Why now — why forward-thinking.** Most people feel no pain yet, because most run one agent.
*That's exactly why now.* The internet's foundational layers — addressing, naming, transport,
trust — were built by people who saw the network coming before it arrived. The ones who built
the *protocols* shaped the next thirty years; the ones who built the *portals* got disrupted.
Agent collaboration is at that same pre-protocol moment. The syntax layer is being decided
right now. The **trust-and-topology layer** — who's in the middle, on whose infrastructure,
under whose authority — is wide open. J3nna Mesh is the bet that the answer should be *yours,
not a platform's*, placed while the question is still ahead of the crowd.

---

## The gap, in one breath

Between **"agents that can talk"** (MCP/A2A are solving the language) and **"agents I can trust
on infrastructure I own"** (nobody has shipped this) lies an empty layer. The market gives you
centralized convenience *or* ungoverned chaos. The **governed-decentralized** quadrant is
vacant. That's what we built — and it's the kind of foundation a substrate-for-everyone has to
stand on.

---

## Who it's for (before they know they need it)

- **Builders of multi-agent systems** who don't want every agent-to-agent call brokered by —
  and visible to — a cloud.
- **Sovereignty-bound orgs** (such as finance, defense, government) whose agents must
  collaborate on-prem, at the edge, or air-gapped.
- **Edge & on-device fleets** — robots, vehicles, kiosks, homes — where a cloud round-trip per
  interaction is a non-starter.
- **Individuals** who want a personal constellation of agents that cooperate on their *own*
  devices, not in someone else's data center.

---

## What it is — and honestly isn't

We'd rather you trust us than be impressed by us, so:

- **It is** a protocol + peer SDK + a control-plane console + a room agent + an events/webhooks
  bridge + an optional embeddable memory engine — a working mesh you run in 60 seconds. Apache-2.0,
  pure-stdlib-leaning Go, tiny dependency tree.
- **It is not** a model runner or a compute marketplace. Agents bring their own inference (local
  Ollama/vLLM or cloud). We're not Bittensor, Akash, or io.net — different problem.
- **It is not** a replacement for MCP or A2A. It's complementary: speak MCP, get governed,
  decentralized topology underneath.
- **Where we're behind:** open-internet reachability. libp2p ships hole-punching, relays, and a
  DHT today; we run over any reachable address — including overlays like **WireGuard/Tailscale**,
  which solve NAT cleanly right now. Today it's an overlay on your existing network. We chose
  to nail *authorization* first, because that's the part nobody else shipped.
- **Maturity:** early. Protocol `JIP/0.1`, components `0.1.0`, unaudited. The trust model is
  implemented and exercised end-to-end by the sample loop. A working foundation, not a hardened
  production deployment.

---

## How we compare (honest)

| | Discovery | Identity | **Authorization** | Open-internet | Runs inference |
|---|---|---|---|---|---|
| **MCP** | central (registry / .well-known) | bearer tokens (OAuth) | optional, AS-centered | yes | no |
| **A2A** | central (Agent Cards) | self-declared, unverified | optional | yes | no |
| **libp2p** | DHT / mDNS | ed25519 (table-stakes) | **none — "left to you"** | **yes (native)** | no |
| **AGNTCY** (LF) | directory (OASF) | Verifiable Credentials | VC-based, incumbent-governed | yes | no |
| **J3nna Mesh** | gossip + multicast | ed25519, pinned | **authorized discovery, root-not-hub, offline-verifiable** | overlay on your existing network | no |

The honest read: ed25519 and capability-advertising are **table-stakes** — we don't claim them
as differentiators. Open-internet routing is a **gap** we close with overlays today. Our wedge
is the one column the others leave blank or hand to a central authority: **authorization built
into discovery itself, with the root off the data path.**



