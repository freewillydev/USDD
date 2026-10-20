# Source qualification, 2026-10-19

- Rust 1.93.0 adapter library: 202 passed, zero failed/ignored, 124.82 seconds
  from the publication tree. Command is in README; test-thread stack 16 MiB.
- Six-ack gate exercises actual retained BIP300 replay with synthetic parent
  proof transcripts. Five acknowledgments reject; six and seven accept without
  M6. Joined V2 and current V7 accounting fixtures execute the burn before using
  the early approval. No parent consensus constants were modified.
- New portable Solidity test: actual simulated EVM payout/duplicate/recipient/
  liability checks pass. Compilation includes the new security-model verifier
  and checks the V4 vault against EIP-170. Proof verification is mocked.
- Retained larger local V4 integration script also passed Rust/EVM journal
  parity, storage-layout equality, partial/full redemption and inbound tests
  with solc 0.8.30. The portable harness pins solc 0.8.37 and Hardhat 3.20.0;
  its tmp 0.2.7 override removes the advisory in the compiler's transitive
  development dependency. npm reported zero known vulnerabilities at validation.
- Vendored/source import preserves upstream whitespace. This is a source
  import, not a clean-whitespace rewrite of retained cryptographic code.

No recursive SP1 proof was generated or verified here, no live funds moved,
and no deployment was performed. Existing guest binaries, keys and deployment
packets must not be reused. This is not a production security audit or Betanet
compatibility claim. Parent receipt mocks do not prove proof-system soundness.
