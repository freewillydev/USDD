# Truthcoin replay boundary

This crate is the deterministic boundary for the separate Truthcoin SP1
receipt consumed by the ECX transition guest. It verifies a mainnet Bitcoin
header chain from an epoch-aligned frozen checkpoint, every index-zero
coinbase inclusion, the exact BIP301 M7 commitment for sidechain 13, Truthcoin
0.17.0's Borsh header codec, BLAKE3 header/body commitments, sidechain ancestry,
BMM parent binding, and deterministic replay/transcript roots. The coinbase
proof intentionally makes no exact transaction-count claim because Bitcoin's
odd-leaf Merkle duplication does not authenticate a unique width.

`execute_replay_with_state_machine` accepts an explicit implementation of
`Truthcoin017StateMachine` for differential tooling. The release guest instead
calls `execute_production_replay`, which is wired exclusively to
`CanonicalTruthcoin017StateMachine`. `PRODUCTION_STATE_MACHINE_LINKED` is true;
the deterministic implementation, not a reviewer signature, selects the
release relation. That implementation is the
zkVM-compatible in-memory port of the complete pinned 0.17.0 UTXO,
authorization, Decision, vote/SVD, market, LMSR, rollback, and selection rules;
review evidence remains useful but is not a consensus or activation input.
Frozen release identities and authenticated witness data remain mandatory.
For every accepted sidechain block it receives the exact raw
timestamp of the M7-containing Bitcoin header, plus ECX's separately derived
Bitcoin MTP, in a transcript-bound context constructed by the structural
verifier. A host-produced trace, timestamp, RPC response, signature, or claimed
state root cannot replace it.

The default guest reproduces the pinned quarterly (7,862,400-second) Decision
cadence. Alpha currently runs upstream's non-testing 86,400-second cadence, so
an Alpha-only guest can be built with `truthcoin-alpha-one-day-period`. That
feature changes replay semantics and therefore produces a different SP1
program ID. An Alpha configuration must bind that exact ID and use the same
genesis/cadence for its oracle schedule; the feature is not an override of the
quarterly production identity.

The structural verifier and canonical state machine port upstream
`Archive::better_tip`, cover committed sidechain forks, and have deterministic
vectors against the patched pinned node. Release remains gated on the frozen
checkpoint/source identities and reproducible artifacts, not outside approval.

Resource use is consensus-bounded at this boundary as well as by the guest's
outer decoder: raw replay evidence is capped at 128 MiB (half of the guest's
256 MiB outer input ceiling), the complete replay at 262,144 Truthcoin transactions,
and the combined exact-template Decision/market
candidate output at 4,096 records. These are aggregate limits in addition to
the per-header, per-block, per-transaction, and per-authorization limits. The
state-machine port must enforce the same candidate ceiling while extracting
records, before growing its output vectors. Candidate selection is a streaming
minimum/maximum scan and does not clone and sort the entire eligible subset.

No ELF, setup key, program ID, or receipt in this repository is a release
artifact. See `zkvm/TRUTHCOIN_RELEASE.md`.

## Offline witness compiler

`ecx-truthcoin-witness-compile` prepares an authenticated node export for the
proof worker. It accepts JSON matching `ReplayInputV1`, verifies the complete
Bitcoin/BMM/body structure, executes the concrete release-candidate state
machine, and writes canonical fixed-integer bincode, candidate-derived public
values, and a hash metadata file. It never changes the production linkage gate
and never generates a proof. A separate implementation or reviewer must
independently reproduce the public values before release proving.
