# ECX forced-action client

This client provides the matcher-independent `ECXF` submission path. It first
decodes and signature-validates the canonical payload, requires the frozen
32-byte chain ID, and then asks an Elements wallet to create, fund, sign, decode,
policy-test, and broadcast the transaction. It verifies that the signed result
contains exactly one byte-identical canonical marker before broadcast.

Remote RPC must use HTTPS. Plain HTTP is accepted only for loopback development.
RPC responses are time- and size-bounded, credentials cannot be embedded in the
URL, and a policy rejection stops before `sendrawtransaction`.

```sh
export ECX_ELEMENTS_RPC_URL=https://elements-rpc.example
export ECX_ELEMENTS_RPC_USER=wallet-rpc-user
export ECX_ELEMENTS_RPC_PASSWORD='from-a-secret-manager'

cargo run -p ecx-forced-action-client --locked -- \
  --payload-hex <canonical-ecxf-payload> \
  --expected-chain-id-hex <64-hex-character-chain-id>
```

The RPC wallet supplies the Elements policy-asset fee input. For production,
use a dedicated least-privilege wallet and RPC identity, TLS authentication,
host rate limits, monitoring, and an independently operated instance rather
than matcher credentials.
