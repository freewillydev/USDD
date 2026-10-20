# Full Alpha recursive adapter SP1 guest (staged)

## V5 custody binary

`alpha-custody-execution-v5` is a separate entrypoint, not the default adapter.
Its single input vector is the canonical 0xb5 `CustodyExecutionWitnessV5`
encoding (bounded to 256 MiB), followed by deferred proofs in execution order.
It uses the V5 lineage and child executor, with actual SP1 deferred verification,
and emits the 144-byte release/statement/parent-context journal. Although the
output layout is retained, the program and release roots differ from V3.
The consumer must independently pin both identities and authenticate the parent
tuple and clock. This binary does not authorize release with arbitrary
caller-selected roots. Its successful target build is not execute-only or
proof compatibility evidence.

This guest wraps `ecx-full-alpha-adapter-v3`. It is a parent-consensus adapter,
not the ECX/BTC conversion guest and not a declaration of proof readiness.

## Input and receipts

Supply one canonical `FullAlphaAdapterInputV3` byte vector (at most 16 MiB),
then supply SP1 deferred proofs in the order consumed by the adapter: the
reviewed Alpha checkpoint receipt first, followed by each full Alpha transition
receipt in sequence. Every deferred receipt must be under the exact canonical
program ID in the input binding and commit to the exact supplied public values.

The marker uses the same tagged SHA-256 convention as the existing Bitcoin and
Elements adapter guests: tag `ECX/truthcoin-sp1-deferred-proof/v1`, with preimage
`program_id || SHA256(public_values)`. It is a public stream-alignment hash, not
a proof. The guest always additionally calls SP1's `verify_sp1_proof` for each
receipt. There is no marker-only or native mock verification fallback.

The output is the existing canonical 529-byte `FullAlphaStatementV3`. It binds
the Alpha consensus profile, explicit recursive binding, checkpoint-relative
state/frontier/event chain and terminal selected state. It does not authenticate
the original checkpoint's history, source event completeness or observation
clocks. It does not supply child BMM-edge, deployment, redemption, quote or
conversion bindings.

## Release boundary

The direct `sp1-zkvm` dependency is pinned to 6.3.1, matching the adjacent Alpha
checkpoint/transition manifests. In the `alpha-adapter-elf.eVcNGy` candidate
stage, the complete lockfile also pins `sp1-lib`, `sp1-primitives` and `slop-*`
to 6.3.1. The source manifests still use semver ranges; use `--locked` and do not
silently regenerate the lockfile. Retain and independently review the
complete lockfile when qualifying a release; a change of that graph requires
requalification and new identity derivation. Do not substitute old ELF/program
IDs or earlier prover artifacts. No program
identity is frozen by this source addition. The external stage's top-level
README records genuine candidate ELF/build/setup evidence, not a production
release or accepted recursive witness. A release must build and
qualify the actual guest, freeze its resulting identity, and independently freeze
the complete `AlphaRecursiveBindingV3` (or its commitment) in the outer consumer.
Caller-selected checkpoint/program IDs are not trust roots.

Native `cargo test --lib` checks only deterministic input-length, canonical-key,
SHA-256 and marker-to-request bindings. It does not execute SP1 verification or
prove that receipts exist. `cargo check --bin ecx-full-alpha-adapter-v3-sp1-guest`
checks the guest API integration, not a zkVM-target guest build or proof run.
