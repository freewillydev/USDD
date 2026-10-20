# ecx-protocol-core

Deterministic protocol primitives for the `ECX-USDD-PERP` market. This crate is
the pure state-transition layer shared by the matcher, proof host, test vectors,
and (through a guest-compatible signature adapter) a zkVM program.

## Consensus rules implemented here

- Eight-decimal integer prices (`PRICE_SCALE = 100_000_000`) and checked integer
  collateral/PnL arithmetic. Floating point is never used.
- BIP340-signed limit orders with chain id, market id, trader key, side, TIF,
  flags, price, quantity, 16-byte client order id, signer fee cap, per-account
  nonce, activation height, and inclusive expiry in the signed message.
- BIP340-signed cancellations and withdrawals, each consuming a fresh account
  nonce. A maker nonce is consumed when the order first enters the committed
  book and is not consumed again when that resting order fills later.
- A persistent, salted `OpenOrderLeaf` tree. The transition verifier selects the
  lowest ask/highest bid, then earliest receipt sequence, then order id. It
  updates remaining quantity and enforces GTC, IOC, FOK, post-only, reduce-only,
  fee-cap, and expiry rules.
- Salted account and position commitments, deterministic keyed Merkle roots,
  deposit/withdrawal nullifiers, order-receipt accumulation, funding, fees,
  initial and maintenance margin, PnL, and cross-margin-only accounting.
- Ordered forced-action and node-derived deposit inbox states, processed
  cursors, authenticated parent-height deadlines, and escape-only overdue
  handling.
- Permissionless liquidations against the exact best eligible resting maker,
  using adverse authenticated bounds, deterministic penalty/insurance bad-debt
  handling, strict position reduction, target-order cancellation, and final
  adverse maintenance recovery.
- Full private-witness verification through:

  ```rust
  verify_transition(&TransitionWitness) -> Result<TransitionJournal, ProtocolError>
  ```

  The verifier recomputes previous/next private roots, batch roots, signatures,
  nonces, book priority, balances, positions, funding, fees, open interest,
  withdrawal debits, and margin. Only `TransitionJournal` needs to leave a proof.
- A canonical frozen configuration binding assets/vault, risk, the
  Truthcoin/LMSR source trust root and schedule, the single central matcher key
  and receipt-chain genesis, forced/deposit domains, and the exact encrypted
  availability scheme plus ordered five-custodian registry hash.
- Deterministic BTC Truthcoin-anchor/LMSR arithmetic with canonical scheduled
  market slots, staleness/boundary/dispute modes, and explicit ECX/USDD
  conversion legs.
- BIP340 central matcher receipts with one configured signer, a contiguous
  global sequence, and previous receipt hash. Exact command coverage and chain
  checks make signed priority attributable but do not provide independent-signer
  failover.
- The cycle-free BMM withdrawal anchor:

  ```text
  A_h = TaggedHash("ECX/perps-m6-state/v1",
        version || slot=24 || child_genesis || checkpoint_height_u32_be ||
        previous_child_block_hash || W_h || R_h)

  marker = "PXST" || 0x01 || A_h
  ```

  `W_h` is the node's existing withdrawal commitment and is preserved. The
  current header hash, BMM critical hash, and M6 id are intentionally absent to
  avoid a hash cycle. The state sequence is already committed inside `R_h`.
  `verify_child_withdrawal_state_commitment` checks an exact four-output M6
  against an `AuthenticatedChildCheckpointV1` inside Elements validation:
  legacy outputs remain in positions 0–2 and the sole canonical PXST must be
  output 3. Parent miners receive only the resulting opaque BIP300 bundle hash
  and the BIP301 commitment to the complete Elements header.

## Canonical encoding

All integers are fixed-width big-endian. Enums are one-byte discriminants and
hashes/keys are raw fixed arrays; there are no varints or implicit lengths in a
consensus object.

| Object | Bytes |
| --- | ---: |
| `LimitOrder` | 144 |
| `SignedLimitOrder` | 208 |
| `CancelOrder` | 137 |
| `SignedCancelOrder` | 201 |
| `TransitionPublicInputs` v4 | 563 |
| `TransitionJournal` v4 | 563 |
| `WithdrawalStateAnchorV1` preimage | 134 |
| PXST marker payload | 37 |

Every hash has a versioned `ECX/...` tagged-hash domain. Exchange state v4 and
transition envelope/journal v4 bind oracle, matcher, forced/deposit,
availability, collateral-settlement, and liquidation commitments without
changing an existing header field. Order signatures use
`ECX/limit-order/v1`; order ids use `ECX/order-id/v1`, so a signature cannot be
replayed across a chain, market, account nonce, or expiry window.

## Confidentiality boundary

Account, position, and open-order leaves are private witness data. Their public
state contains only salted commitments and Merkle roots. A fresh unpredictable
32-byte salt is required for every leaf rotation; the crate rejects the all-zero
salt but cannot measure randomness. Commitments are not encryption and plain
Rust execution is not private. Public-chain confidentiality comes only when the
witness stays inside the prover. The signed matcher necessarily sees plaintext
orders and the sequencer/prover sees plaintext positions in this profile. The
separate witness-availability crate encrypts recovery data and requires three
of five registered custodians; the scheme and registry hashes are frozen here,
but production confidentiality still depends on correct independent operation.

## Production gates not provided by plain Rust

This crate deliberately does not pretend that host-supplied external facts are
authenticated:

1. The source-pinned Truthcoin proof envelope and native LMSR recomputation are
   integrated through proof-core, but the reviewed full Bitcoin/BMM/Truthcoin
   replay program and production verifier do not exist yet. The default
   verifier rejects every envelope; a keeper signature is not oracle truth.
2. Node-derived `ECXD` events, confidential deposit openings, exact vault
   settlement, withdrawal output coverage, and USDD conservation are
   implemented and host-tested. They are not a substitute for activation and
   audit of the node overlay, vault, assets, and Simplicity/proof identities.
3. Forced cancel/reduce-only-IOC/withdrawal consumption and exact permissionless
   liquidation witnesses are implemented. Outage liveness still requires an
   independently operated witness-recovery/proving/submission path.
4. Native signing/verification currently uses `libsecp256k1`. An SP1 build should
   use its supported BIP340 syscall/adapter while preserving the exact 32-byte
   signing digest and 64-byte signature encoding.
5. Central matcher receipt verification, atomic journal replay, authenticated
   node synchronization, and the header-derived forced inbox are implemented.
   The matcher remains intentionally non-quorum; an independent backup prover
   and production availability deployment remain operational requirements.

Until those gates and the node/covenant integration are active, this is a
coherent testnet/proof profile, not a production custody system.

## Verification

```sh
cargo test -p ecx-protocol-core
cargo clippy -p ecx-protocol-core --all-targets -- -D warnings
```
