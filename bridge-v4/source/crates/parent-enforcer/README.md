# ECX header-only miner commitment adapter

The production API is `verify_miner_header_commitment`. It gives a miner the
smallest ECX-specific interface possible: one exact serialized Elements
critical-header preimage, one locally accepted BIP301 commitment, and local
child-header ancestry. It has no Truthcoin, matcher, Simplicity, SP1, private
witness, or M6 transaction input.

It checks only:

- the exact slot-24 BMM commitment already accepted by the parent enforcer;
- the exact critical-header preimage, with only the BMM proof field cleared;
- the locally tracked child-header predecessor, version, length, and height;
- the presence of the existing withdrawal bundle commitment and additive ECX
  roots in that committed header; and
- the authenticated parent height used by that header.

The returned roots are opaque commitments, not a miner assertion that an ECX
transition is semantically valid. Elements full nodes validate the singleton,
Simplicity program, proof, Truthcoin-derived oracle state, and canonical PXST
while constructing and accepting the child block. BIP301 commits the complete
hashable Elements header. Standard BIP300 processing separately votes on and
settles the opaque withdrawal bundle hash already carried by that header.

`verify_parent_miner_pxst_approval` remains temporarily behind the non-default
`legacy-pxst-reference` feature as a test-only reference for the superseded
semantic parent hook. The `ecx-protocol-core` dependency is optional and is
pulled in only by that feature. Production builds must use the empty feature set
and must not wire the legacy entrypoint into a miner vote path.

The crate has no RPC/database client and no dependency on the upstream
`bip300301_enforcer` repository. Raw header transport may be untrusted; decoded
RPC fields are never security inputs.
