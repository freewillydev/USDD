# ECX encrypted witness availability

This crate supplies the availability and recovery layer for confidential ECX
transition witnesses. It is independent of the central matcher and of the
proof implementation. It never authorizes an order, state transition, header,
or withdrawal.

## Cryptographic profile

- The witness is encrypted with XChaCha20-Poly1305 under a random 256-bit key
  derived with HKDF-SHA-256 from a nonzero Ristretto scalar.
- The scalar is split with a degree-two polynomial into exactly five shares.
  Any three reconstruct it. Three Ristretto Feldman commitments let every
  custodian and recovery client reject a malformed share before using it.
- Each share is independently encrypted with XChaCha20-Poly1305 under a key
  derived from ephemeral-static X25519 and the bundle's canonical header hash.
- Each custodian uses a separate Ed25519 key to attest its validated plaintext
  share. A recovery certificate is three to five valid signatures from distinct
  registered custodians. It is a threshold quorum certificate, not an
  aggregate signature and not matching consensus.
- The canonical binary manifest and all ciphertexts are content-addressed by a
  tagged SHA-256 bundle root. The caller-supplied nonzero 32-byte `context`
  must be the transition/batch identifier committed by the proved state.

`FrozenConfigurationV1::availability` commits the exact scheme hash, ordered
five-custodian registry hash, threshold, count, and 16 MiB size limit. Changing
an algorithm or registered key therefore changes the singleton configuration
hash instead of reinterpreting an existing bundle.
Proof-core additionally canonicalizes the supplied bundle, binds its
context/root to the availability-neutral transition recovery payload, matches
the compiled scheme and configured registry, and verifies the payload AEAD plus
all five share envelopes and Feldman openings. It also requires three distinct
custody receipts signed only after each service has synced the immutable file,
decrypted its envelope, and checked its Feldman share. This proves threshold
receipt at transition time, not future retention or service.

All primitives come from maintained RustCrypto and dalek crates. Secret scalar,
share plaintext, derived AEAD keys, loaded key files, bearer tokens, and
recovered witness buffers are zeroized on drop where their APIs permit it.

## Library flow

1. Provision five `CustodianSecrets` on five independent hosts and publish only
   their `CustodianPublic` values in canonical index order 1 through 5.
2. Call `create_bundle(context, witness, custodians)` and send the exact bytes
   returned by `WitnessBundle::encode()` to independent custodians. Collect at
   least three post-persistence `CustodyReceiptV1` values and include them in
   `ProofInputV1`; the transition proof rejects a smaller or invalid set.
3. Commit `WitnessBundle::root()` in the transition's availability metadata.
   During recovery, retrieve the exact root from multiple stores. Each
   custodian calls `CustodianSecrets::attest`; the method decrypts the assigned
   envelope, checks its index and Feldman commitment, and only then signs.
4. Call `verify_recovery_certificate` and `recover_witness` with at least three
   distinct contributions. Recovery rechecks every supplied signature and
   share, interpolates the scalar, and authenticates the payload ciphertext.

The parser rejects unknown versions/domains, noncanonical indices, any count
other than five, thresholds other than three, malformed curve keys or
commitments, duplicate custodian keys/nonces, incorrect fixed lengths, trailing
bytes, zero contexts, non-contributory X25519 keys, and witnesses over 16 MiB.

## Service API

`ecx-witness-availability serve` exposes a deliberately small API:

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/health` | Unauthenticated readiness identity: protocol, role, custodian index, and public X25519/Ed25519 keys; contains no secrets. |
| `POST` | `/v1/bundles` | Validate, atomically persist, decrypt/check the local share, then return the root and non-revealing custody receipt. |
| `GET` | `/v1/bundles/{lowercase-root}` | Retrieve the exact canonical binary bundle. |
| `POST` | `/v1/bundles/{lowercase-root}/attest` | Decrypt, validate, and attest this service's share. |

Every `/v1` request is authenticated before its body is buffered. Upload,
retrieval, and recovery-share routes require three distinct bearer credentials,
so compromise of a producer credential cannot release a custodian share.
Bundle bodies use `application/octet-stream`; responses other than bundle
retrieval use JSON. The daemon bounds body size, concurrent requests, handler
time, and moves filesystem/cryptographic work off the async network workers.
The store is append-only and content-addressed. Writes use a synced temporary
file plus an atomic no-overwrite link; an existing root is accepted only when
its complete canonical bytes match. Reads reject symlinks, oversized files,
corrupt encodings, and root mismatches.

The health identity is checked against the frozen deployment manifest. A
generic replica reports role `replica` and null custodian fields; it must never
be counted toward the three required custody receipts. A custodian reports
role `custodian` and the public keys derived from the secret key file it
actually loaded, so endpoint or key substitution cannot pass by returning a
generic `ok` response.

Service construction also runs a bounded durability canary in the configured
store: create-new, write, file fsync, exact readback, unlink, and directory
fsync must all succeed, and the canary must be gone afterward. Startup fails
otherwise. Existing stores must be non-symlink private directories. Successful
health includes `storage: durable_write_verified_at_startup`, which the
whole-system readiness gate requires; restarting services is part of a storage
recovery drill because this field intentionally describes the startup test,
not a promise that later hardware failure is impossible.

Each store also holds a process-lifetime exclusive `.ecx-store.lock`; two
writers can never serve the same directory. Stop the service and audit a store
before copying it to backup media and again after restoring it:

```sh
cargo run -p ecx-witness-availability -- audit \
  --store-dir /var/lib/ecx/custodian-1
```

The audit verifies every private regular `64-lowercase-hex.ecxw` file through
the canonical decoder and content root, rejects foreign/temporary/symlinked
entries, and enforces hard one-million-bundle and 16-TB aggregate ceilings. It
prints the bundle count, exact byte count, and a deterministic SHA-256
inventory commitment over sorted `(root, length)` entries. The command requires
an existing store and the exclusive lock, so a path typo cannot create an
apparently valid empty backup and a live writer cannot race the inventory.

Generate a custodian key file without overwriting an existing path:

```sh
ecx-witness-availability keygen --index 1 --output custodian-1.json
chmod 600 upload-token read-token recovery-token
ecx-witness-availability serve \
  --store-dir /var/lib/ecx-witness \
  --upload-token-file upload-token \
  --read-token-file read-token \
  --recovery-token-file recovery-token \
  --custodian-key-file custodian-1.json
```

The three tokens must be different. The daemon refuses group/world-readable key
or token files, refuses to replace key files, defaults to loopback, and
requires an explicit override for a non-loopback bind. Put it behind
authenticated TLS or mTLS; the daemon itself does not terminate TLS. Configure
per-client rate limits, connection limits, disk quotas, retention, and disk
monitoring at that edge. Deploy at least three custodians and multiple
ciphertext stores in independent failure domains.

## Production key separation

Never derive or reuse these keys with one another:

- matcher BIP340 receipt key;
- prover credentials;
- availability API bearer/mTLS credential;
- custodian X25519 encryption key; and
- custodian Ed25519 share-attestation key.

Each custodian host holds only its own X25519 and Ed25519 secret keys. The
bundle producer receives public keys only. The recovery signature grants no
ledger authority, and a malformed share is rejected even if a compromised
attestation key signs it. Rotate the public registry only through a proved,
versioned configuration transition; never reinterpret an existing bundle under
a new custodian set.

Before real assets, use an HSM or isolated signer for the Ed25519 key, protect
the X25519 key with equivalent controls, run backup/restore drills, audit the
canonical encoding and recovery ceremony, and test loss of any two custodians.

The whole-system host/reference E2E creates a real bundle, requires three valid
custody receipts in the proof relation, commits its root as the successor
availability root, collects three recovery contributions, and recovers the
exact private bytes. It does not simulate independent hosts, production TLS/key
custody, future retention, or a real SP1 proof.
