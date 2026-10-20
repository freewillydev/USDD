# Alpha parent-only M7 relation (partial integration)

This is **not an ECX/BTC conversion program**, a native Alpha child proof, or
proof-readiness evidence. Do not install its program ID as
`-ecxbondv2ecxbtcprogramid`. The existing Signet relation is unchanged.

## Implemented boundary

`src/conversion_parent_link_v3.rs` composes the existing real Alpha checkpoint
and transition receipt chain. Its guest is
`../../zkvm/full-alpha-adapter-v3-guest/src/bin/alpha-conversion-parent-link-v3.rs`.
The production guest calls SP1 `verify_sp1_proof` for every underlying receipt;
matching a marker alone cannot succeed. The host verifier trait is a dependency
injection boundary, not authentication by itself. Tests use an explicitly
synthetic transcript verifier and deliberately unmined fixtures; they do not
produce or validate cryptographic proofs.

For the final single selected-chain extension P -> Q, it authenticates the exact
predecessor state, final full block, authenticated terminal header/state and
all-slot fixed Alpha BIP300 replay. Slot 24 must have the exact frozen proposal
and activation height in P and Q. Q must contain exactly one recognized M7 for
slot 24 whose opaque critical commitment matches the requested internal hash.
The requested parent anchor must be P, never Q. Earlier parent transitions keep
the existing frontier/reorganization semantics. The final transition must have
one step, no intervening deployment-state change, and matching discovery order.

The 266-byte journal is explicitly distinct from the 275-byte economic ABI:

| Bytes | Meaning |
| --- | --- |
| 0 | Version `0xa4` |
| 1 | Purpose `0`, parent/opaque-M7 only |
| 2..258 | Eight 32-byte hashes in order: fixed Alpha profile, frozen binding, parent statement, predecessor state, terminal state, Q hash, P hash, opaque M7 critical hash |
| 258..262 | Q height, big-endian u32 |
| 262..266 | M7 coinbase output index, big-endian u32 |

A consumer must verify the correct rebuilt guest program and independently
freeze/check `binding_commitment`. It includes parent source/checkpoint and
role-specific checkpoint/transition program IDs, declared child configuration,
genesis/checkpoint, and slot-24 deployment. The child fields are **declared
consumer bindings only**: this parent relation cannot authenticate a child
checkpoint. A caller-selected checkpoint/program is not a trust root. The
reviewed-checkpoint guest authenticates a reviewed preimage, not genesis replay.

## Explicitly rejected / still required

Any nonempty `candidate_child_block`, `NativeChildAndParentLink`, or
`EconomicConversion` request fails before receipt processing. There is no child
transaction indexing and no accepted legacy child fallback. Parent-only success
does not prove any M7 preimage, ELMTP coinbase, native child block/UTXO/scripts,
peg-in, parent deposit confirmations, unspent reserve, withdrawal accumulator,
or economic conversion. In particular, native one-confirmation acceptance is
not an authenticated receipt.

To complete the outer relation, a real native Alpha child transition/deposit
guest must prove the frozen child branch and consensus/UTXO execution, canonical
ELMTP parent P, withdrawal-accumulator transition and resulting native critical
hash. A versioned recursive outer consumer must verify that receipt and this
parent receipt, cross-bind P/Q, slot 24, critical hash and all frozen network,
checkpoint and program identities, then derive the economic journal from the
authenticated deposit/UTXO/reserve state. It also needs independently reviewed
checkpoint inputs, a real SP1 build/program freeze and byte-exact execute-only
qualification. None of those are claimed here.

## Native source cross-check (read-only)

Reference root:
`/Volumes/T705/SERVERRR/alpha-pegin-current-master.mhj4q0/source`.
These source references establish format semantics, not a reviewed release hash
or live-chain compatibility proof.

- `src/mainchainrpc.cpp:994`: M7 payload carries opaque ConsensusHex
  **display-order** bytes; parser uses `reverse_copy` into uint256 internal
  bytes. `:1092` repeats this in unique M7 extraction. The new relation reverses
  exactly once; tests use a non-palindromic commitment and reject wrong endian.
- `src/mainchainrpc.cpp:3644`: native child commitment is one canonical
  `OP_RETURN PUSH37 ELMTP || parent_internal_hash`. `:3677` rejects nonminimal,
  duplicate, or trailing tagged encodings. This is not a bare 32-byte push.
- `src/validation.cpp:371`: native `ComputeWithdrawalBip301CriticalHash` hashes
  domain/version, displayed child genesis, slot, displayed exact child block
  hash, previous/next withdrawal counts and roots. `:498` derives it from the
  predecessor's persisted consensus accumulator, not caller RPC data.
- `src/drivechain_bmm.cpp:765`: slot-assigned native Elements explicitly rejects
  the historical BMM proof header extension. `doc/drivechain-bmm-proof.md:3`
  identifies that extension as historical Liquid-signet only. Accordingly the
  new relation does not import or accept the patched legacy child codec.

## Reproduce native checks

From the source root, with every cache/output on the external drive:

```sh
export RUSTUP_HOME=/Volumes/T705/rustup
export CARGO_HOME=/Volumes/T705/code/caches/cargo
export CARGO_TARGET_DIR=/Volumes/T705/SERVERRR/alpha-conversion-integration.6iRnSa/target-alpha
export TMPDIR=/Volumes/T705/SERVERRR/alpha-conversion-integration.6iRnSa/tmp
/Users/lukekensik/.cargo/bin/cargo +1.93.0 test --offline --manifest-path crates/full-alpha-adapter-v3/Cargo.toml
/Users/lukekensik/.cargo/bin/cargo +1.93.0 check --offline --manifest-path zkvm/full-alpha-adapter-v3-guest/Cargo.toml --bin alpha-conversion-parent-link-v3
```

On 2026-09-03 these completed with 19 native tests passing (12 new boundary
tests, 7 existing adapter tests), and native guest type-check successful.
Logs are `alpha-parent-link-tests.log` and `alpha-parent-link-guest-check.log`
in the enclosing stage. No SP1/RISC-V ELF build or program-ID qualification was
performed for this new guest. No proof run was performed.

No canonical profile, proof gate, live node, wallet, network, deployment or paid
compute was modified by this implementation.
