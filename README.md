# RetroShare-Next

Friend-to-friend encrypted p2p suite, rewriting [RetroShare](https://retroshare.cc)'s feature set in
modern Rust: chat, file transfer, forums/channels and a web of trust — over QUIC with automatic NAT
hole-punching, instead of the 2006-era TCP + PGP certificate ceremony.

Design invariants (unchanged from RetroShare):

- **F2F trust only.** No global identity, no server to register with. You vouch for a friend's key.
- **End-to-end encrypted**, always.
- **Zero cloud dependency.** A node works on a LAN or between two home connections with nothing
  hosted in between.

## Status

| Milestone | Scope | State |
|---|---|---|
| M0 | workspace, Ed25519+X25519 identity, 4×4 fingerprint | done |
| M1 | invite deep link, Noise_XX handshake, DM | done |
| M2 | iroh/QUIC transport, files with resume + sha256 + rate limit, forums with merkle sync | done |
| M3 | headless control plane, event stream, web of trust, channels & read positions, loopback web bridge | in progress (desktop shell remains) |
| M4 | local AI: Ollama assistant, sqlite-vec semantic search, summaries | planned |
| M5 | MLS group chat, post-quantum hybrid key exchange, self-hosted relay/DNS | planned |
| M6 | mobile (Tauri mobile) + Home Node wizard | planned |

Everything claimed as *done* is covered by automated gates; see [Verifying](#verifying).

## Build and run

The toolchain lives in a container so nothing is installed on the host:

```bash
docker run -d --name rsnext-dev -u "$(id -u):$(id -g)" \
  -v "$PWD":/src -v rsnext-target:/target -v rsnext-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src rust:1-bookworm sleep infinity

docker exec rsnext-dev cargo build --workspace
B=/target/debug/rsnext-node
```

Two nodes, two friends:

```bash
$B init Alice a_dir                      # writes a_dir/identity.json (private keys!)
$B init Bob   b_dir
$B net a_dir 7801 &                      # daemon: QUIC listener + control socket
$B invite2 a_dir PAIRCODE 127.0.0.1:7801 > inv.txt
$B accept  b_dir "$(cat inv.txt)"
$B p2p-send  b_dir <endpoint_id> 127.0.0.1:7801 <alice_fp> "hello"
$B p2p-push  b_dir <endpoint_id> 127.0.0.1:7801 <alice_fp> /src/somefile
$B p2p-pull-all b_dir <endpoint_id> 127.0.0.1:7801 <alice_fp>   # take everything offered that we do not already hold
$B channel-post b_dir crypto "first post"
$B p2p-sync  b_dir <endpoint_id> 127.0.0.1:7801 <alice_fp>
$B ban  b_dir <peer_fp> "spam"            # permanent refusal, outranks an existing friendship
$B bans b_dir                              # inspect the list (reason included)
$B presence b_dir                          # peers: declared state if fresh, else observed
$B status   b_dir away 120                 # what we announce about ourselves
$B circle-create b_dir family               # a named set of friends
$B circle-add   b_dir family <peer_fp>     # add a member

$B restrict b_dir secret family            # this channel is only ever sent to circle members
$B forget  b_dir channel notes             # erase locally; tombstones keep it erased across syncs
$B forgotten b_dir                         # audit what was erased (and therefore must not return)
RSNEXT_STATUS_TICK=4 $B net b_dir 7802     # opt-in heartbeat (rides `hi`, off by default)
$B unban b_dir <peer_fp>                   # restore delivery without re-pairing
$B wiki-save b_dir Manual "page text"    # append a revision to a wiki page
$B wiki-show b_dir Manual                # current revision (newest ts, deterministic tie-break)
$B wiki-history b_dir Manual             # every revision, never overwritten
$B channel-list b_dir                    # posts / read position / unread per channel
$B search  b_dir "walnut crypto"          # deep index: words AND-ed, BM25 ranked, retroshare:// hits
$B search-status b_dir                    # index vs truth: docs == posts + offered files
$B search-rebuild b_dir                   # repair path; must not change what is searchable
$B wot-sign  b_dir <alice_fp>            # vouch for a friend's full identity
$B wot-trust b_dir                       # local trust scores from the signature graph
```

## Control plane

`net` also serves newline-delimited JSON-RPC on `./rsnext.sock` (mode 0600, never TCP):

```bash
$B rpc a_dir node.info
$B rpc a_dir chat.send '{"to":"<fp>","text":"hi"}'
$B rpc a_dir channels.list
$B events a_dir                          # subscribe: chat | file | forum | peer-bonded
```

A loopback HTTP + SSE bridge exposes the same surface for a web UI or a remote thin terminal:

```bash
$B web a_dir 127.0.0.1:8780              # bearer token in a_dir/web.token (0600)
```

## Architecture

| Crate / module | Responsibility |
|---|---|
| `rsnext-core::identity` | Ed25519 signing key + X25519 key agreement, human fingerprint |
| `rsnext-core::handshake` / `channel` | hand-written Noise_XX and the ChaCha20-Poly1305 transport |
| `rsnext-core::store` | SQLite: messages, posts, channels, subscriptions, files, peers, certificates |
| `rsnext-core::merkle` | per-channel append-only log roots |
| `rsnext-core::wot` | certificate format, signature verification, trust propagation |
| `rsnext-node::net` | iroh endpoint, F2F pairing gate, file transfer with resume and content-addressed batch pull, rendezvous |
| `rsnext-core::store` (circles) | named friend sets + per-channel send restriction, enforced on the **outbound** sync path for posts, roots and channel definitions alike |
| `rsnext-core::presence` | presence: last authenticated contact (thresholds 120s/900s) merged with a peer's self-report; a stale report falls back to observation, and `source` says which was used |
| `rsnext-core::store` (bans) | ban list enforced as the first check in the pairing gate, so a revoked friend cannot deliver even with a valid identity proof |
| `rsnext-core::wiki` | collaborative pages over the channel log: append-only revisions, deterministic current version |
| `rsnext-core::deepsearch` | persistent inverted index (posts + offered files), BM25 ranking, maintained inside the mutators |
| `rsnext-node::rpc` | unix-socket JSON-RPC + `events.subscribe` push channel |
| `rsnext-node::web` | loopback HTTP + SSE bridge |
| `rsnext-node/feed` | RSS/Atom polling: guid dedupe, per-feed error isolation, size cap |

Two properties are worth knowing before changing this code, because both were bugs found by the
gates rather than by reading:

- An iroh `Endpoint` owns the UDP socket. A `Connection` outliving it looks healthy while carrying no
  data, so `dial()` returns `(Endpoint, Connection)` and callers keep both.
- Only a process that keeps listening may publish an address. A short-lived CLI dialing from a
  throwaway port will otherwise overwrite a friend's good record with a dead one, so the advertised
  address is captured once at daemon bind time and read everywhere (`my_addr` on requests,
  `peer_addr` on replies).

## Verifying

```bash
bash tools/gates.sh
```

Runs unit tests plus five suites against a real multi-container network (one container per node,
default bridge):

| Suite | Covers |
|---|---|
| `cargo test` | handshake math, F2F authorization decisions, merkle/WoT semantics, storage migrations |
| `gates_m2.sh` | pairing, one-time code, replay rejection, files with resume, rate limit, forum convergence, events, socket permissions |
| `gates_u123.sh` | credential rules, concurrent-transfer exclusivity, restart self-healing |
| `gates_wot.sh` | certificates bind the full identity, forged issuers dropped, trust propagation |
| `gates_channel.sh` | per-channel roots converge independently, read positions and unread counts; deep-index invariants (index == posts + offered files, hooks fire on local and replicated writes, BM25 ordering, AND semantics, unshare removes the document, rebuild changes nothing) |
| `gates_mesh.sh` | three-node addressing: fixed ports and friend-assisted rendezvous |
| `gates_files.sh` | batch pull: zero re-download, dedupe across renamed copies, replace on name conflict, resume from a partial, refusal for unbound peers |
| `gates_rss.sh` | feed polling: first fetch, guid dedupe on re-poll, incremental items only, per-feed error isolation, feed channel replicates and converges |
| `gates_forget.sh` | erased rows stay erased when a peer re-offers them (tombstones), the search index is cleaned in the same operation, later posts in the same channel still replicate, and the gate asserts the limit too: a friend's copy is untouched |
| `gates_circles.sh` | a peer outside the circle receives neither the posts, the merkle root, nor the channel definition of a restricted channel - while the same round still delivers an unrestricted one; removal and unrestricted restore take effect immediately |
| `gates_presence.sh` | contact recorded only past the pairing gate (a refused stranger never appears), aging crosses the documented thresholds, unknown peers have no timestamp rather than epoch 0, a self-report reaches the peer by heartbeat, a live friend stops aging out while heartbeating, and no background dialling happens unless the switch is set |
| `gates_ban.sh` | ban outranks an authenticated binding, nothing is delivered while banned, refusal reason logged, list survives a daemon restart, unban restores |
| `gates_wiki.sh` | append-only page revisions, both replicas agree on the current revision and the channel root, pages replicate as pages, invalid names and empty saves refused |
| `gates_web.sh` | loopback HTTP bridge: bearer-token gate, SSE event stream, no external bind |

The suites share containers and pinned UDP ports, so they must not run concurrently; `gates.sh`
takes a lock and refuses an overlapping run. `XFAIL` lines are tracked open items (see `PLAN.md`),
never silent passes.

## Repository layout note

Node data directories (`a_dir/`, `b_dir/`, …) are **not** tracked: `identity.json` holds private
keys. Never commit or ship them.
