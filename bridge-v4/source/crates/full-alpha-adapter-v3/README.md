# Full Alpha recursive parent-consensus adapter

This new, separate adapter consumes the post-fork Alpha executed-state and
transition ABIs. It does not reinterpret a Signet receipt or replace the existing
Bitcoin/Elements adapters. Its output is **not** an ECX/BTC conversion proof or a
production-readiness assertion.

The consumer must freeze `AlphaRecursiveBindingV3` (or its tagged commitment):
the execution-source configuration commitment, exact reviewed checkpoint-input
commitment, and the two rebuilt checkpoint/transition program identities. The
execution-source configuration must not hash its own checkpoint preimage; the
outer binding combines these independent values without a circular commitment.
No production binding, reviewed checkpoint, or program identity is supplied here.

## Relation and trust boundary

`checkpoint_alpha_v3` strictly decodes a canonical reviewed Alpha checkpoint,
validates its state and selected-frontier membership, and commits the exact input,
Alpha consensus profile, all-slot BIP300 state, frontier and event cursor. Its
277-byte journal starts with `0xa3`. It checks reviewed **structure and exact
commitment**, not genesis history, completeness of source events, a chosen UTXO
root's provenance, or the authenticity of observation clocks. Those remain
independent source-review requirements.

`execute_full_alpha_adapter_v3` requires verification of the exact checkpoint
receipt and every nonempty, sequential full-Alpha transition receipt. It binds
source, selected state/height, frontier, event stream and contiguous discovery
sequence, then checks the terminal executed-state preimage and its all-slot state,
deployment context, tip, MTP and chainwork. Selected height is not required to
increase on every discovery event: the authenticated best leaf may remain the
same. The final 529-byte fixed bincode journal is separately version/profile bound.

`FullAlphaReceiptVerifierV3` is a required cryptographic-verification interface,
not an implementation. A production SP1 verifier/guest and a frozen outer consumer
are still needed. The test-only transcript verifier models this boundary to test
linkage and fail-closed calls; its synthetic transitions are not real receipts or
live-replay evidence. There is no production marker-only fallback.

`zkvm/reviewed-alpha-checkpoint-v3-guest` is a source wrapper for this new checkpoint
relation. No ELF, SP1 setup, program ID, execute-only result or proof was generated
or claimed. Rebuilding and independently deriving the actual identities is
mandatory; prior Signet IDs are not compatible by assertion.
The attempted offline lock generation was blocked because the external registry
cache cannot resolve `sp1-zkvm = 6.3.1`; the failure is recorded in
`logs/checkpoint-alpha-guest-lock.log` at the isolated stage root. This wrapper has
not been compiled, and its absence of a generated lockfile is not a pinned runtime.

## Native checks

Run in the isolated source root, using Rust 1.93.0 and the stage's external caches:

```sh
cargo +1.93.0 test --locked --offline --jobs 1 --manifest-path crates/full-consensus-validator-v2/Cargo.toml --no-default-features --lib
cargo +1.93.0 test --locked --offline --jobs 1 --manifest-path crates/full-alpha-adapter-v3/Cargo.toml --all-targets
cargo +1.93.0 test --locked --offline --jobs 1 --manifest-path crates/full-consensus-validator-v2/Cargo.toml --all-targets
cargo +1.93.0 test --locked --offline --jobs 1 --manifest-path crates/full-bitcoin-adapter-v2/Cargo.toml --all-targets
cargo +1.93.0 test --locked --offline --jobs 1 --manifest-path crates/full-elements-adapter-v2/Cargo.toml --all-targets
```

Native results in this isolated stage: 104 no-default validator library tests;
120 default validator library tests plus 8 Alpha header integration tests;
7 new adapter tests; 1 existing Bitcoin adapter test; 6 existing Elements adapter
tests. All passed. The default all-targets run reported 7 ignored Core corpus tests;
none of those corpus tests was executed or newly qualified by these commands.
The first adapter build found a private helper import; the final source uses a
local tagged SHA256 helper, and the final adapter rerun passed. Both initial failure
and final test logs are preserved under the stage's `logs` directory.

The outer Alpha ECX/BTC relation, recursive verifier integration, authenticated
checkpoint/source records, rebuilt IDs, real deployment/genesis, and fresh witness
are still separate prerequisites. This code must not fill their profile fields
with synthetic test values or promote `proofReady`.
