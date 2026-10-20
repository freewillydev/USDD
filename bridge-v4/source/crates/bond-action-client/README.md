# ECX v2 bond action client

This crate is the fail-closed wallet boundary between the desktop gateway and
an independently operated v2 transition producer. It does **not** build a
proof-free bond transaction. A subscription, redemption enqueue, or
cancellation is valid only as part of the exact confidential Elements
transition consumed by the v2 proof and Simplicity covenant.

For every action the client:

1. reads the patched Elements node's authenticated ECX context directly;
2. requires the matcher capital projection to equal the node projection;
3. requires the configured private-chain ID;
4. fetches the producer API-v3 status, validates the complete
   `FrozenConfigurationV2` preimage against the node-pinned hash, and derives
   every asset/script/profile identity locally before any prepare request or
   signature is released;
5. sends an unsigned intent to the transition producer;
6. checks the producer's prepared context against a fresh active-chain read;
7. recomputes the deterministic NAV allocation and every proof-statement
   opening commitment from the exact confidential settlement openings;
8. for redemption enqueue, renders the exact per-intent V18 keyless staging
   P2TR script locally, fixes the signed refund height to the authenticated
   parent plus the frozen inclusion and refund windows, and rejects a producer
   that substitutes either the serialized output or a longer lock;
9. signs the canonical protocol-core action locally;
10. encrypts the exact fixed-width signed payload and requires independently
   verified 3-of-5 post-persistence custody receipts;
11. signs the canonical 503-byte amount-free inbox marker locally;
12. independently verifies the producer-composed raw source transaction,
    input-zero annex, marker, frozen configuration, and enqueue staging output;
    and
13. calls `testmempoolaccept`, broadcasts through the local Elements wallet
    RPC, and confirms the exact txid remains in the mempool.

The producer is liveness-only. Its response is accepted only as a candidate
raw transaction; it cannot assert broadcast, proof consumption, or finality.
The client returns `disposition=broadcast` only after the local checks above,
and always returns `consensus_cursor_advanced=false`: mempool admission does
not mean the proof/node consumed the inbox entry. Missing producer, node,
capital, custody receipts, wallet scripts, raw transaction, or proof gates
returns a structured blocker and never a synthetic receipt.

Capital-mode preflight mirrors the proof relation before the producer sees an
intent: redemption enqueue is Normal-only, cancellation remains available in
Normal and ReduceOnly, and Recovery permits only subscriptions and explicit
non-dilutive recapitalization. A mode-rejected enqueue cannot acquire a
producer nonce or reach transaction construction/broadcast.

At mempool broadcast time the source entry does not yet have an authenticated
observed parent height, so the client refuses to guess an absolute processing
deadline. The receipt leaves `process_deadline_parent_height` unset and
reports the frozen six-parent-block rule separately. Once included, the exact
deadline is the source entry's authenticated observed parent height plus six;
an unprocessed action then expires without consuming its account nonce or
changing balances.

Redemption enqueue reports the signed refund-available parent height
separately from the mandatory-processing deadline. The current tree does not
yet contain a production Simplicity witness/program/control-block renderer for
the refund leaf, so this client does not fabricate a holder-refund
transaction. That lane remains fail-closed until the patched node exposes the
frozen leaf material and the wallet can construct and locally sign the exact
two-input, three-output spend. A refund broadcast will not itself claim that
the proof inbox cursor advanced.

All HTTP endpoints must be loopback or HTTPS. Set an exact expected chain ID so
the local wallet cannot be pointed at a different network by changing only a
URL:

```sh
export ECX_BOND_EXPECTED_CHAIN_ID=<64-lowercase-hex>
export ECX_BOND_EXPECTED_CONFIGURATION_HASH=<64-lowercase-hex>
export ECX_BOND_EXPECTED_ASSET_ID=<64-lowercase-hex>
export ECX_BOND_EXPECTED_DEPLOYMENT_COMMITMENT=<64-lowercase-hex>
export ECX_BOND_EXPECTED_TRANSITION_PROGRAM_ID=<64-lowercase-hex>
export ECX_BOND_EXPECTED_SIMPLICITY_TRANSITION_CMR=<64-lowercase-hex>
export ECX_ELEMENTS_RPC_URL=http://127.0.0.1:18884
export ECX_ELEMENTS_RPC_USER=<local-rpc-user>
export ECX_ELEMENTS_RPC_PASSWORD=<local-rpc-password>
export ECX_MATCHER_URL=http://127.0.0.1:8088
export ECX_TRANSITION_PRODUCER_URL=http://127.0.0.1:8092
export ECX_BOND_RECIPIENT_SCRIPT_SHA256=<64-lowercase-hex>
export ECX_BOND_HOLDER_SCRIPT_SHA256=<64-lowercase-hex>
export ECX_USDD_DESTINATION_SCRIPT_SHA256=<64-lowercase-hex>

ecx-bond-action-client status
ecx-bond-action-client subscribe --key-file trader.json --contribution-usdd-atoms 100000000
ecx-bond-action-client recapitalize-insurance --key-file trader.json --contribution-usdd-atoms 100000000
ecx-bond-action-client enqueue-redemption --key-file trader.json --bond-share-atoms 100000000
ecx-bond-action-client cancel-redemption --key-file trader.json --request-id <64-hex>
ecx-bond-action-client transfer --destination <confidential-address> --bond-share-atoms 100000000
```

`transfer` is the sole ordinary holder-to-holder lane. It validates a
confidential destination and uses an Elements PSET v2 with
`include_explicit=true`. Before extraction it independently verifies the
explicit-value range proof and explicit-asset surjection proof against the
recipient's confidential commitments. It then locally decodes the finalized
transaction, requires the same script and commitments, calls
`testmempoolaccept`, broadcasts, and confirms mempool presence. This works for
an external recipient whose blinding secret the sender does not possess while
still binding the exact asset and atom count. It returns
`disposition=broadcast` and a txid. Proof-managed actions use the same honest
broadcast label only after their exact authenticated inbox source transaction
is independently checked and seen in the local mempool.

## Offline physical deployment candidate

`ecx-bond-v2-deployment-plan <private-spec.json> <create-new-plan.json>`
constructs the confidential fixed-supply inventory and low-level Elements
objects from explicit private prevouts, scripts, asset IDs and blinding
material. It derives the adaptive confidential-issuance VBF needed to balance
the inventory's nonzero ABF/VBF and builds the inventory surjection proof over
the complete regular-input plus issuance domain. It runs Elements' amount,
range and surjection verifier over both resulting transactions before writing
the plan. Both input and output contain private opening material and must not
be published. The create-new plan and candidate writers use mode 0600 on Unix;
this is not encryption or a substitute for a protected runtime directory.

The specification requires `issuance_previous_transaction_hex`,
`deployment_sponsor_previous_transaction_hex` and
`genesis_sponsor_previous_transaction_hex` in addition to each selected txid
and vout. The canonical transaction bytes must match that txid and contain the
selected output. The issuance input must hold exactly one explicit
state-authority atom; each sponsor must hold an explicit policy-asset amount.
All three outpoints must be distinct, including across the two transactions.
Only native P2WPKH, P2WSH and valid P2TR inputs are supported, so later
witness-only signing need not change the candidate txids. These offline checks
do not establish ownership, unspentness, maturity or active-chain inclusion.

`deployment_fee_atoms` and `genesis_fee_atoms` specify exact positive fees.
Surplus is returned in an explicit policy-asset output to the corresponding
`deployment_change_script_hex` or `genesis_change_script_hex`. These optional
fields must be absent/null for exact-fee inputs and supplied for surplus inputs.
The builder never assumes that an input equals its fee and never silently adds
surplus or dust to that fee. It refuses insufficient inputs, missing change
scripts and unsupported/unspendable change scripts. The caller must separately
verify that each destination is controlled by the intended wallet and that
the final transaction meets node relay/fee policy; no address is hardcoded.

`ecx-bond-v2-deployment-candidate <plan.json> <create-new-output.json>` builds
the canonical unsigned two-transaction initialization outside the frozen proof
source graph. Tx1 orders the confidential fixed-supply inventory, explicit
token burn, and one-unit state-authority output at indexes 0, 1, and 2. Tx2
spends Tx1:2 at input zero and creates the explicit P2TR singleton at output
zero. The tool reuses the settlement issuance/opening verifier, independently
checks the cross-transaction linkage, refuses to overwrite output, and fixes
all funding/signing/mempool/confirmation/freeze/activation claims to false.
Wallet funding, witness signing, active-chain confirmation, identity freezing,
and node activation are separate required steps; this command claims none of
them.

After Tx1 has established the asset ID and deployment commitment and the exact
V2 configuration template has been composed, first run
`ecx-bond-v2-derive-deployment-configuration <candidate.json>
<frozen-configuration-v2-template.json> <create-new-configuration.json>`.
It validates the candidate and template, replaces only the physical asset,
deployment, vault-script, state-authority, USDD, and fixed-supply identities,
then validates and writes the resulting configuration without making an
authority claim. Next run
`ecx-bond-v2-bind-deployment-candidate <candidate.json>
<frozen-configuration-v2.json> <create-new-bound-output.json>`. This second
create-new record validates the complete configuration and binds its digest,
bond/deployment identities, inventory/queue/burn scripts, state-authority and
USDD assets, fixed supply, and the separately node-frozen singleton script.
All authority flags remain false; the bound record is still not funding,
confirmation, identity-freeze, or activation evidence.

`ecx-bond-v2-export-configuration-fixture <configuration.json>
<create-new-fixture.txt>` emits the exact canonical length, tagged digest, and
bytes needed by the node/Simplicity cross-language decoder boundary.
`ecx-bond-v2-verify-deployment-binding <bound-candidate.json>` independently
revalidates a persisted binding record and every false authority flag.

A loopback-only unactivated Elements-regtest exercise confirmed a corrected
Tx1/Tx2 pair after both passed `testmempoolaccept` and preserved their unsigned
candidate txids under witness signing. The exact pair was subsequently rebound
to a newly derived 1,977-byte candidate configuration and reverified by both the
Rust relation and the private evidence verifier. The candidate manifest commits
a deterministic recursive closure of all Rust/TOML sources in the seven local
production crates reachable from the deployment client, plus the workspace
manifest/lock/configuration and exact V18 configuration/renderer fixtures. It
also pins the resulting file count. Indirect source additions or changes now
make the evidence stale instead of silently retaining a green status; build
outputs are deliberately excluded. This remains neither a BMM-authenticated
network result nor an SP1
proof, frozen identity, or activation. It also demonstrated that the historical
V18 explicit-issuance shape cannot be retained: its deployment and proof
identities must be superseded atomically rather than relabeled.

The repaired source-local configuration bytes are therefore stored under the
explicit candidate-only fixture
`Testing/v18-config-v2-confidential-issuance-candidate.txt`; the historical
V18 fixture and its digest remain unchanged. The plan boundary rejects a VBF
that is not the unique balancing counterpart of the inventory opening, an
explicit issuance paired with the blinded inventory, a missing issuance range
proof, and a substituted complete surjection domain.
