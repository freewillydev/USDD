# ECX V2 conversion verification foundation

This crate reuses real verification code from `ekulkisnek/USDD`. The original
Bitcoin/Ethereum foundation remains pinned by Cargo to commit
`2c9dc7a72052240613deba3d9cf52a43403368d4`. The ECX/BTC relation separately
pins the stronger Bitcoin/BIP300 implementation at
`a0a72d1abf4687172b77175af8c90758fe43e028`; keeping the dependencies aliased
prevents an ECX upgrade from silently changing the USDD/USD source graph.

It exposes three narrow, fail-closed operations:

- continuous LayerTwo Signet header linkage, retarget, proof-of-work and
  cumulative-chainwork verification from an exactly deployment-pinned
  checkpoint; and
- Sepolia beacon light-client SSZ/BLS/finality verification with exact binding
  to the finalized execution state root.
- a versioned canonical ECX/BTC witness/relation that replays LayerTwo Signet
  block/PoW/MTP, expanded slot-24 BIP300/BIP301 state (including exact optional
  M6 artifacts), BMM-bound Elements block continuity, checkpoint/covenant
  commitments, confidential-opening shape, reserve arithmetic, and two
  mandatory recursive full-validity statements.
- a versioned canonical USDD Ethereum-source witness that directly verifies
  the pinned Sepolia Helios finality transition and exact MPT account/storage
  branches for deployment-frozen reserve, liability, pause, governance and
  quote slots, then emits a fixed 457-byte recursive statement.

The ECX/BTC guest and an offline candidate composer are present, but this is
not yet a releasable conversion receipt producer. The candidate composer never
uses RPC and cannot cryptographically verify compressed subreceipts. The guest
requires distinct full Bitcoin and full Elements recursive receipts; those
reviewed programs, deployed identities, and authenticated witnesses do not yet
exist. In particular, no code here turns an operator-provided exchange rate,
reserve, supply, UTXO root, or storage slot into authenticated state. The
remaining blockers and required composition are listed in
`docs/CONVERSION_PROOFS_V2.md`.

Both git source revisions must appear verbatim in `Cargo.lock`. Updating either
commit is a source change requiring a fresh audit, tests, guest build and
program identity.

The crate's default feature set retains all source-local host/test adapters.
SP1 guests deliberately disable defaults: ECX/BTC enables only `ecx-btc`, and
the Sepolia source guest enables only `usdd-ethereum`. This prevents the
Bitcoin guest from accidentally compiling the Helios graph. The Ethereum guest
patches only `ethereum_hashing 0.7.0`'s runtime SHA-256 backend from `ring` to
pure-Rust `sha2`, because SP1's bare RISC-V target has no C standard library.
Fixed/differential hashes pass and the complete guest now builds; Helios SSZ,
BLS, fork, and finality code is not replaced.

The strict file-manifest shape for the offline ECX candidate composer is shown
in `zkvm/conversion-artifacts/ecx-btc-candidate-files.v1.template.json`. Every
path must name an already exported local regular file. The command performs no
node RPC or network access and only writes an explicitly suffixed
`.ecxbtc-v2.candidate`; it is not a receipt exporter.

`usdd-usd-ethereum-witness-export` is also strictly offline and file-backed.
Unlike the ECX candidate composer, it directly runs the complete Ethereum
finality/MPT relation before writing canonical guest input; its output still is
not an SP1 receipt. It cannot replace the separately missing authenticated
Bitcoin/BMM/Elements USDD source receipt or establish that a selected token is
legally and unconditionally redeemable for USD.

Its strict local file-manifest shape is
`zkvm/conversion-artifacts/usdd-ethereum-source-files.v1.template.json`.
Relative paths resolve from the manifest directory, every MPT node is a
separate bounded file, and the metadata JSON must leave every file-backed byte
vector empty. Placeholder names in the template are not deployment identities
or authenticated evidence.

```sh
cargo run --locked --features exporter \
  --bin usdd-usd-ethereum-witness-export -- \
  <local-file-manifest.json> <new-output.usdd-ethereum-v2.witness>
```
