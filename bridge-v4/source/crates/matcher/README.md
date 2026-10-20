# ECX matcher

`ecx-matcher` is the replayable signed central-limit order book for the single
`ECX-USDD-PERP` market. It uses integer protocol units, maker-price execution,
and FIFO ordering within a price level.

The checked-in HTTP service deliberately uses exactly one configured central
matcher signer. Every accepted placement or cancellation receives one
BIP340-signed, hash-chained ingress receipt from that key. The receipt binds the
exact trader command, global sequence, previous receipt hash, parent
observation, forced-inbox cursor, and availability commitment. On the
node-backed path, that signed availability commitment also binds the complete
atomic Elements context: tip hash, exchange root, forced/deposit roots and
counts, and BMM parent hash/height/MTP.

## Trust boundary

- Production placement is accepted only after reconstructing the exact
  `ecx-protocol-core::LimitOrder` and verifying its BIP340 signature through
  `SignedLimitOrder::verify`. The returned order ID is the protocol-core ID.
- Production cancellation follows the same rule through `SignedCancelOrder`.
- A matcher receipt attributes ordering to the configured server; it is not a
  custody authorization or a substitute for the SP1/Simplicity transition
  checks. The matcher cannot forge a trader signature or make an invalid state
  transition settle.
- Public order-book and trade data reveals prices and time/sequence only; it
  omits quantities, counts, order/trade IDs and counterparties. The matcher
  itself necessarily sees trader keys, signed orders and exact fills. Account
  and position data is confidential to public chain observers, not to this
  central matcher.
- The account endpoint reports `provisional: true`: its position is an
  immediate matcher preview, not final state, until the batch is accepted by
  the proof-verified state transition.

Prices and ECX quantities use eight decimal places (`100_000_000` protocol
units per displayed unit). A production `client_order_id` is exactly 16 bytes
encoded as 32 lowercase hex characters. It is signed as part of the canonical
order and also keys idempotent HTTP retries.

## Run

From the repository root:

```sh
ECX_MATCHER_SECRET_KEY_FILE=/run/secrets/ecx-matcher.json \
ECX_CHAIN_ID=<64-hex-sidechain-id> \
ECX_ELEMENTS_RPC_URL=https://elements.internal.example \
ECX_ELEMENTS_RPC_USER=<rpc-user> \
ECX_ELEMENTS_RPC_PASSWORD=<rpc-password> \
cargo run -p ecx-matcher -- \
  --listen 127.0.0.1:8088 \
  --journal data/matcher.jsonl
```

V2 additionally requires every frozen singleton identity pin and a protected
raw bearer-token file (`ECX_PROOF_PRODUCER_TOKEN_FILE`) containing 32--4096
non-whitespace characters. The file is read without following symlinks and
must deny group/other access on Unix. Give that token only to an authorized
transition proof producer over an authenticated encrypted channel. Activating
V2 requires an empty resting book and disables new `/v1/orders` placements:
those frozen-wire orders have no proof-required signed margin selection and
must never be mixed into a V2 settlement batch. The V1 schema and non-V2
deployment behavior remain unchanged; cancellations stay available.

Outside demo mode, the matcher key, frozen sidechain ID, and patched Elements
RPC endpoint are required. Remote RPC must use HTTPS; plaintext HTTP is
accepted only for a loopback endpoint. Credentials cannot be embedded in the
URL and must be supplied as a complete username/password pair. Create the
protected key document with `ecx-matcher-keygen`; the matcher checks its size,
regular non-symlink identity, private permissions, schema, and embedded public identity before
starting. Direct `ECX_MATCHER_SECRET_KEY` input remains available for migration
and hermetic automation, but production deployments should use the file.

For the bundled no-funds demo:

```sh
cargo run -p ecx-matcher -- --demo --chain-height 12345
```

`--demo` is explicit: only then may `demo-*` traders omit signatures, and only
then is permissive browser CORS enabled. Never enable it on a funded service.
The `ECX_ALLOW_STATIC_CONTEXT_FOR_TESTS` escape hatch is rejected by release
builds even when set; it exists only for debug/test fixtures.

The lifetime-safe incremental successor uses a separate binary and private
wire surface; it is never inferred from the finite matcher configuration:

```sh
cargo run -p ecx-matcher --bin ecx-successor-matcher -- \
  --listen 127.0.0.1:8089 \
  --journal data/successor-matcher.bin \
  --successor-configuration-file data/incremental-successor-v2.json \
  --matcher-secret-key-file data/successor-matcher.key \
  --proof-producer-token-file data/successor-proof.token \
  --trader-state-authority-public-key <64-hex-x-only-key> \
  --activation-height <frozen-height> \
  --matcher-key-epoch <frozen-key-epoch> \
  --matcher-genesis-sequence <canonical-u128> \
  --matcher-genesis-receipt-hash <64-hex> \
  --elements-rpc-url http://127.0.0.1:7042 \
  --elements-rpc-user <rpc-user> \
  --elements-rpc-password <rpc-password> \
  --bond-action-configuration-hash <64-hex> \
  --bond-asset-id <64-hex> \
  --bond-deployment-commitment <64-hex> \
  --successor-transition-program-id <64-hex> \
  --successor-transition-cmr <64-hex>
```

Startup recomputes the outer successor, order, and matcher configuration
identities from the full configuration preimage and requires the node's exact
`incremental-successor` profile. Its `/successor/v2/orders` and cancellation
routes journal before publishing; bearer-protected `/successor/v2/proof/*`
routes stream deterministic proof-complete entries after a canonical decimal
`u128` admission cursor. Placement additionally requires a BIP340-signed,
tip/config/order-bound trader-state grant from the pinned private proof-state
authority. The grant binds the authenticated exchange-state root, trader order
generation, salt, and parent context before the journal fsync; the successor
proof still opens and verifies the trader leaf independently. This is
source-tested plumbing, not an activated network: current public identities,
physical activation, authenticated source receipts, and the outer successor
proof producer remain unfrozen or absent.

The separate proof-state process can issue that grant only from a full public
state preimage whose canonical root equals the current node projection and a
typed one-trader Merkle opening against that state's trader root:

```sh
cargo run -p ecx-matcher --bin ecx-successor-trader-state-grant -- \
  --successor-configuration-file private/successor-config.json \
  --successor-public-state-file private/current-public-state.json \
  --trader-read-proof-file private/trader-read.json \
  --signed-order-file private/order.json \
  --matcher-recovery-file private/order-recovery.json \
  --authority-secret-key-file private/trader-state-authority.key \
  --output-grant-file private/order-grant.json \
  --elements-rpc-url http://127.0.0.1:7042 \
  --bond-action-configuration-hash <64-hex> \
  --bond-asset-id <64-hex> \
  --bond-deployment-commitment <64-hex> \
  --successor-transition-program-id <64-hex> \
  --successor-transition-cmr <64-hex>
```

Private inputs and the authority key must be regular, non-symlink files with
mode 0600 on Unix; the output is create-new and fsynced. The issuer never
accepts a caller-provided exchange root without re-reading the authenticated
node context. Producing the public-state preimage and typed read path remains a
proof-composer responsibility; this tool does not synthesize either one.

For a long-running private boundary, the grant service reads only exact
`<exchange-root>-<trader>.json` snapshots from a mode-0700 store. Each snapshot
contains the full public-state preimage and one typed trader read proof. The
service verifies the signed order and risk commitment, reads the authenticated
node context before and after the snapshot, rejects a moving tip, and issues a
fresh-salt grant only when every root, height, matcher cursor, trader and
generation matches:

```sh
cargo run -p ecx-matcher --bin ecx-successor-trader-state-service -- \
  --listen 127.0.0.1:8090 \
  --successor-configuration-file private/successor-config.json \
  --trader-snapshot-directory private/trader-snapshots \
  --authority-secret-key-file private/trader-state-authority.key \
  --authority-public-key <64-hex-x-only-key> \
  --bearer-token-file private/trader-state.token \
  --elements-rpc-url http://127.0.0.1:7042 \
  --bond-action-configuration-hash <64-hex> \
  --bond-asset-id <64-hex> \
  --bond-deployment-commitment <64-hex> \
  --successor-transition-program-id <64-hex> \
  --successor-transition-cmr <64-hex>
```

`ecx-successor-order-client` signs the disjoint u128 order and risk commitment
from a protected trader key, obtains this grant, submits the exact
order/recovery/grant triple, verifies the matcher configuration and all
returned admission/execution signatures, and writes a create-new mode-0600
receipt. It refuses an existing output before any remote request. This closes
the local signing/submission seam; it does not construct the snapshot, produce
the recursive successor proof, or activate a network.

For the desktop gateway, pass `--nonce-state-file` and `--valid-for-blocks`
instead of caller-selected nonce, order ID, or heights. The private high-water
file is exclusively locked and fsynced before any request; a crash may burn a
nonce but cannot reuse it. The client first binds current successor health to
the exact configuration, trader-state authority, capital mode, durable receipt
head, proof-consumed cursor, and authenticated sidechain/parent heights. Its
stdout is a compact verified admission document; the full signed grant and
matcher response remain in the create-new private receipt file. Admission is
not proof settlement and clients must not present it as confirmed.

Before every placement or cancellation, and before reporting healthy readiness,
the matcher calls the patched node's `getecxconsensuscontext` RPC. When the tip
advanced, it also checks the last trusted sidechain block with `getblockhash`
and re-reads the atomic context to close a moving-tip race. It advances order
liveness to the authenticated active Elements height and signs that height,
BMM parent height/time, and the complete node-observed forced-inbox count into
the receipt. Height, time, inbox, or source-parent regressions; deep or
same-height reorgs; a moving context; or inconsistent append-only inbox roots
fail closed before the command or journal can mutate. The process then requires
operator reconciliation instead of silently following an alternate history.
Proof verification remains the final authority on order liveness.

RPC connect and whole-request timeouts are two and five seconds. RPC responses
are limited to 64 KiB and must carry the exact JSON-RPC version and request ID.
Hashes use exact lowercase fixed-width hex, and the source-parent height must
equal the BMM snapshot height.

For V2 admission the node projection must be version 3 and root-bind the
covenant, bond/funding states, full price range, FIFO queue, oracle certificate
and freshness endpoint, encrypted-availability commitment, bond inbox
head/processed/outcome cursors, node-verified source head, and matcher execution
batch/cursor. The matcher combines capital and oracle modes conservatively,
rejects a stale oracle, and stops matching if a non-normal mode is reached while
non-reduce-only orders are still resting. The availability root proves the
accepted transition's custody threshold; it is not a live custodian-health
signal.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Mode, active height, engine sequence, and signed receipt-chain head |
| `GET` | `/v1/markets/ECX-USDD-PERP/orderbook` | Aggregated depth |
| `GET` | `/v1/markets/ECX-USDD-PERP/trades` | Recent fills |
| `GET` | `/v1/markets/ECX-USDD-PERP/ws` | Book/trade/order stream |
| `POST` | `/v1/orders` | Signed limit placement plus central matcher receipt |
| `POST` | `/v1/orders/{id}/cancel` | Signed cancellation plus central matcher receipt |
| `GET` | `/v1/accounts/{trader}` | Provisional private account view |
| `POST` | `/v2/orders` | V2 risk-bound placement; exact execution receipts return only to its signed taker |
| `GET` | `/v2/proof/execution-receipts` | Bearer-authorized contiguous execution receipts plus signed taker admissions |
| `POST` | `/successor/v2/orders` | Successor `u128` signed placement on the dedicated service |
| `POST` | `/successor/v2/orders/cancel` | Successor `u128` signed cancellation on the dedicated service |
| `GET` | `/successor/v2/proof/head` | Bearer-authorized successor journal head and node identity |
| `GET` | `/successor/v2/proof/entries` | Bearer-authorized deterministic successor proof-entry suffix |

Production account reads require `x-ecx-view-timestamp`,
`x-ecx-view-nonce`, and `x-ecx-view-signature` headers. The V2 signature binds
the exact canonical trader path, timestamp, and 16-byte nonce. It expires after
30 seconds and a bounded in-process cache rejects reuse. TLS and edge-level
rate/connection limits are still required; the cache is not a durable
cross-restart authorization ledger.

JSON mutations reject unknown fields and bodies over 16 KiB. HTTP handlers
have a ten-second deadline. WebSocket messages/frames are limited to 4 KiB and
slow sends are dropped after five seconds.

The newline-delimited journal stores each command, its central-matcher receipt,
and—on the node-backed path—the complete Elements context in one record, then
flushes and syncs it before staged state becomes visible. A V2 placement also
stores every exact signed fill receipt, its dedicated contiguous execution
cursor and chained history commitment in that same fsynced record. Receipts
bind the exact maker/taker orders and fill economics to the signed V1 taker
admission. An ordinary fill is economically timestamped only at the
proof-authenticated transition prior-parent MTP; its receipt locator must equal
that exact tip and cannot select an older funding hour. The file is
private
(`0600` on Unix), exclusively locked, and each record is limited to 64 KiB.
Startup verifies the receipt signature, command/context binding, sequence,
previous hash, and context progression while replaying the book. A malformed,
oversized, empty, or unterminated line fails startup rather than silently
recovering a different book. A write/sync failure poisons the live journal so
later mutations cannot continue. Retrying an already accepted signed command
returns its original receipt instead of allocating a new sequence.

Every V2 fill batch is also written to a separate private (`0600` on Unix),
append-only, length-framed execution archive. Its prepare record is fsynced
before the journal mutation; after that mutation is fsynced, a hash-chained
commit record is fsynced before staged engine state becomes visible. Startup
finishes a fully written prepare that has a durable journal entry, explicitly
aborts an otherwise valid orphan prepare, and rejects partial, truncated,
reordered, or hash-tampered frames. The archive is streamed rather than loaded
wholesale and is never exposed by a public market endpoint.

At `ECX_COMPACT_JOURNAL_BYTES` the matcher creates private BIP340-signed
snapshot envelope version 5. It commits the execution archive genesis, exact
referenced head and record count, plus only the unconsumed hot receipt suffix;
then it atomically installs and fsyncs the snapshot before truncating the
journal and dropping consumed hot receipts. The proof-verified active-tip PV5
cursor is the only pruning authority. A reorg to any lower cursor streams and
rehydrates the exact contiguous signed receipts and taker admissions from the
archive; missing or inconsistent history fails closed. This prevents archive
growth from forcing the bounded 256 MiB snapshot to grow with lifetime fill
count. V1 journal/snapshot readers and wire payloads remain frozen. Other old
commands remain nonce-protected but their original receipt may no longer be
available. `ECX_MAX_TRADERS` bounds the trader/account index.

Node-backed legacy receipt records use the frozen earlier formats; the additive
V2 execution record is journal entry version 4 and signed snapshot envelope
version 5. A nonempty legacy production journal without the full signed context
requires explicit operator migration/reconciliation; it is not silently
upgraded. Fresh V2 activation assumes the dedicated execution cursor starts at
zero; migration from a previously active nonzero V2 cursor remains an explicit
release operation, not inferred restart behavior.

Production priority is the centrally signed global action sequence, never
`received_at_ms`. Local time remains display metadata. See
[`docs/CENTRAL_MATCHER.md`](../../docs/CENTRAL_MATCHER.md).

This one-server design is intentionally non-quorum. Server outage, censorship,
signing-key loss, or compromise is a matching-liveness and sequencing-safety
failure. The live Elements-node integration and on-chain forced inbox provide a
matcher-independent consensus path. Completing outage recovery still requires
an independently operated prover/submitter and independently deployed encrypted
witness stores and custodians; those roles do not turn matching into a quorum.

The forced escape path deliberately does not call this matcher. A wallet must
put the canonical protocol-core `ECXF` payload in a transaction sent directly
to the patched Elements node; node consensus orders it and the proof consumes
it without a matcher receipt. The canonical payload codec, node validation,
inbox tracking, deadline, and proof rules are present. A production wallet
transaction builder, fee/coin-selection service, broadcaster, independently
operated prover, and escape submitter remain deployment gates.

The engine has deterministic global/per-trader order, trader, and per-height
command limits, and the journal has signed bounded compaction. The
`ecx-matcher-backup` utility provides an offline exclusive-lock backup of the
journal, snapshot, and execution archive; manifest v2 binds every file hash
and archive genesis/head/count. Restore verifies and replays the complete set
at a create-new target before reporting success.
Production operation still needs replication of those verified backup
directories to independent media/failure domains, scheduled drills,
metrics/alerts, edge request controls, and isolated or HSM-backed matcher-key
custody.

The additive successor runtime is deliberately separate from that V1 service.
It accepts only the fresh successor signed order/cancel wire, retains the exact
signed risk selection, trader generation, private order-index salt and
full-`u128` admission priority, and signs each exact fill under the successor
execution domain. A command is fully staged against a cloned proof-shaped book
before its identity-bound append is fsynced; only then is the in-memory book
swapped. Streaming restart re-verifies and reconstructs the same book without
loading an unbounded command history. This runtime is source-tested but is not
yet exposed by HTTP or the desktop, and it is not a proof producer or activated
consensus identity.

## Verify

```sh
cargo test -p ecx-matcher
```

The tests cover price-time priority, maker pricing, IOC/FOK and post-only
preflight, self-trade prevention, nonce/idempotency behavior, cancellation,
position previews, canonical production signatures/IDs, account-credential
replay, HTTP/RPC bounds, exclusive and partial-record journal recovery, full
context tamper/restart checks, central receipt-chain verification, idempotent
receipt recovery, authenticated node-context advancement and active ancestry,
forced-inbox cursor binding, expiry at the active height, and no-mutation
failure on reorg or regression. V2 tests additionally cover exact multi-fill
receipt issuance, contiguous cursors, private proof-producer authorization,
public-payload non-disclosure, raw-journal and signed-snapshot restart,
admission retention, proof-cursor rollback with byte-identical re-export,
omission and signature tamper rejection.
Successor tests additionally cover high-`u128` price/time fills and execution
receipts, byte-exact journal replay, failed-stage atomicity, wrong-chain startup,
owner-bound cancellation, and cancellation replay.
