# Local V4 bridge: six-ack Ethereum exits

This imports the newer local V4 vault and its retained Rust adapter/guest source
into USDD without replacing the older top-level implementation. It is source
for qualification, **not a deployed or production-qualified bridge**. No node,
enforcer, mainchain consensus parameters, or existing Ethereum deployment is
changed by this import. The retained parent adapter is the Alpha profile; this
publication does not claim a Betanet deployment or qualification.

## Ethereum approval rule

- Slot 24 must contain the exact proposed blinded bundle in authenticated replay.
- Require six net M4 acknowledgments: score >= 7, because the M3 proposal starts
  at score 1. The proposal itself is not an acknowledgment. Alarms and competing
  upvotes reduce the score according to the unchanged parent replay rules.
- `CustodyAckBundleV3` opens the bundle's version, locktime, fee and checkpoint
  commitment. Its ID is calculated with the same blinded serialization as M6.
  It is not a spendable transaction, mined M6, or permission to spend L1 escrow.
- The checkpoint commitment must match the independently executed burn and
  frozen custody identity. The burn must consume the sidechain UTXO and supply;
  failure of a later parent withdrawal must not refund that burn.
- An early-approved bundle must remain pending with sufficient score through
  the selected finality endpoint. Score loss, expiry, removal and ancestry
  substitution fail closed. After an actual M6, use the retained mined-M6 path.
- Ethereum still checks pinned proof/configuration identities, canonical parent
  finality, recipient, amount, asset, custody domain, liability and spent burn ID.

Six acks are deliberately weaker than full BIP300 voting. A later reorganization
or miner reversal cannot claw back an Ethereum payout. The proof establishes
the policy, not irreversibility. Parent finality depth and freshness are separate
requirements and have not been reduced.

## Witness and deployment changes

Set `CustodyHistoryWitnessV2.approval_bundle = Some(CustodyAckBundleV3 { ... })`,
`approval_transaction` to that bundle's computed ID, and `approval_index` to the
authenticated qualifying block. The history wire tag is now `0xb3`; old `0xb2`
bytes reject. `None` retains the stronger mined-M6 route. All custody execution
entrypoints, including accounting V7, use this selection.

Release/policy hashes now include the required-ack count as a big-endian u16
after the minimum-confirmation count. V4 and its candidate redemption verifier
use `USDD_ELEMENTS_BURN_SLOT24_SIX_NET_ACKS_V1` as the security-model label.
The `approvedM6id` ABI field remains the blinded bundle ID, not a claim of an L1
spend. Existing V2 contracts and their security-model label remain unchanged.

**Old guest IDs, verification keys, release hashes, compiled contracts, custody
IDs and deployment packets are invalid for this update.** Rebuild and qualify
the guest, derive/pin its new program and release identities, regenerate the
deployment graph, then deploy new immutable contracts before live use. Never
point the new contract at an old proof or a mock verifier. No live proofs or
deployment credentials are included here.

## Tests

From the repository root (Rust 1.93.0):

```sh
RUST_MIN_STACK=16777216 cargo +1.93.0 test --locked \
  --manifest-path bridge-v4/source/crates/full-alpha-adapter-v3/Cargo.toml --lib -j 1
cd bridge-v4/contracts
npm ci
npm test
```

The larger test-thread stack accommodates the existing deep execution fixtures.
Rust coverage includes 0-5 ack rejection, 6/7 acceptance without an M6, bundle
preimage substitution, slot substitution, invalid receipts, alarm/score loss,
pre-approval branch rejection, wire roundtrip/version rejection, and joined
executed-burn/V7 accounting paths. Solidity tests exercise actual EVM contracts
with mocked proof boundaries: partial/full payouts, insufficient liabilities,
recipient binding and duplicate burn rejection. Neither suite is a genuine
recursive-SP1 proof, live-chain test, or complete bridge security audit.

The source includes retained adapter dependencies and vendored secp256k1-zkp
with its original license. Local deployment artifacts, build outputs, operator
configuration, private keys, and environment-specific examples are excluded.
