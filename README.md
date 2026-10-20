# USDD protocol workspace

The newer local V4 bridge and six-ack slot-24 Ethereum exit candidate are in
[`bridge-v4`](bridge-v4/README.md). They are qualification source, not a deployed
upgrade; see its release-identity and proof limitations before use.

This workspace contains the deterministic USDD bridge protocol model and the
in-progress Ethereum and Simplicity integrations:

- schema-2 canonical encodings and domain-separated identifiers;
- protocol records for the locked V1 irreversible mint/burn flow;
- the fixed-depth burn accumulator and sequential nonce replay protection;
- reserve/supply audit invariants;
- honest host-testable proof statement cores with strictly typed journals;
- a dependency-light command-line utility;
- protocol specifications and fixed test vectors.

The `contracts` and `simplicity` directories consume these consensus encodings.
Their presence is not evidence that the end-to-end proof systems are complete;
see `BUILD_STATUS.md`, `SECURITY_REVIEW.md`, and the mandatory launch gates.

The proof core does not pretend that a boolean or an RPC response proves chain
finality. It exposes verifier traits, and the Ethereum inbound crate now
implements the Sepolia trait with pinned Helios SSZ/BLS consensus verification.
That native verifier and the SP1 source wrapper are not an on-chain proof
artifact: Elements validity plus canonical Bitcoin/BMM ancestry and the
reproducible SP1 build/proof gates remain blocked.

Schema 2 removes Bitcoin parent time from prover-controlled Ethereum inputs.
The Ethereum journal commits only the execution timestamp proved by Ethereum;
the Elements controller must compare it with parent MTP obtained from its own
authenticated block-validation environment. Outbound state carries a full
Elements consensus-state digest so validity proofs can advance incrementally
without treating a tip hash as a UTXO commitment.

V1 has exactly one canonical issuance path: finalized Ethereum USDT deposits
mint the native Elements asset. Tron is not a second mint authority. Tron and
other chains may support separately specified atomic inventory swaps, but those
swaps neither issue USDD nor alter canonical backing.

## Workspace

- `crates/usdd-core`: consensus-facing data model and audit logic.
- `crates/usdd-proof-core`: verifier boundaries and deterministic public
  outputs suitable for an SP1-style guest adapter or another transparent VM.
- `crates/usdd-ethereum-inbound`: bounded, `no_std` Ethereum vault
  account/code-hash and deposit-storage proof verification plus an optional
  native Sepolia verifier pinned to Helios consensus core commit `204c998a...`;
  a real Sepolia fixture passes its SSZ, BLS, finality, and execution checks.
- `crates/usdd-bitcoin-bmm`: bounded, `no_std` Bitcoin header, exact
  block/transaction/Merkle/BIP141, PoW, chainwork, LayerTwo Signet, canonical
  slot-24 M7/M8, and positive-only M1/M2/CTIP replay primitives; it deliberately
  does not claim contextual Bitcoin, full BIP300, or Elements validity.
- `crates/usdd-sp1-verifier`: pinned SP1 6.3.1 host verification for canonical
  raw compressed proofs and SHA-256-only typed public values; it is not an
  Elements jet or an Ethereum verifier contract.
- `crates/usdd-cli`: IDs, encodings, burn-accumulator operations, manifest commitments,
  and audit checks.
- `guests/ethereum-state`: exact SP1 6.3.1 source entrypoint and bounded input
  wrapper. It host-compiles, but no zkVM ELF/program ID or proof is claimed.
- `simplicity`: canonical formats, the fail-closed mint-controller design, and
  a source-only, compiler-checked inventory HTLC whose node-compatible CMR is
  deliberately not frozen yet.
- `specs`: normative byte formats, state machines, proof statements, and
  deployment manifest requirements.

See `BUILD_STATUS.md` before treating any interface as a completed bridge. In
particular, this workspace supplies no production SP1 guest binary or complete
Elements/Bitcoin proof circuit yet. The Ethereum finality source path is
implemented, but its zkVM artifact and proof gates remain incomplete. The
launch-gate report therefore defaults to BLOCKED.

## Development

```sh
CARGO_TARGET_DIR=/path/to/build-cache cargo test --workspace --all-features --locked
CARGO_TARGET_DIR=/path/to/build-cache cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
CARGO_TARGET_DIR=/path/to/build-cache cargo test --manifest-path guests/ethereum-state/Cargo.toml --locked
python3 scripts/verify_sp1_provenance.py
(cd typescript && npm run check)
(cd contracts && npm test)
python3 -m unittest discover -s simplicity -p 'test_*.py' -v
```

The full workspace currently requires Rust 1.88 or newer because the pinned
SP1 verifier package declares that minimum; the protocol-only crates retain
their lower per-package minimums.

No trusted bridge signer, watcher quorum, MPC key, or optimistic challenger is
represented in this workspace. Off-chain provers and relayers are permissionless
and affect liveness only.

USDT amounts are encoded in six-decimal micro-USDT units. USDD is an
eight-decimal Elements asset, so every mint and burn uses the exact conversion
`USDD base units = USDT micro-units × 100`. Mint replay protection is the
controller's monotonically consumed per-vault deposit nonce. Deposits, mint
batches, and individual burns are capped at 20,000,000 USDT so every accepted
transition fits beneath Elements' transaction-wide explicit-output limit with
fixed headroom for authority, fee, and change outputs.

## Permissionless reserve reconstruction

`usdd-cli audit replay <vault-balance> <recorded-liability> <events.tsv>`
reconstructs deposits, sequential mints, finalized burns, and payouts; rejects
duplicate IDs, nonce/index gaps, amount or recipient mismatches, and replay;
then checks reserve/supply conservation. The strict TSV header is
`kind<TAB>index<TAB>id<TAB>amount<TAB>recipient`. This command validates the
reconstruction, not the authenticity of its input: production indexers must
derive the rows from independently validated Ethereum and Elements chain data.
