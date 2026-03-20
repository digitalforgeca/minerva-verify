# minerva-verify

Standalone CLI tool for verifying Minerva ZK-STARK proofs.

Verify any Minerva proof from the command line — no account, no API key, no private data needed.

## Install

```bash
cargo install minerva-verify
```

## Usage

```bash
# Verify a proof file
minerva-verify proof.json

# Verify multiple proofs
minerva-verify proof1.json proof2.json

# JSON output
minerva-verify --json proof.json

# Read from stdin
cat proof.json | minerva-verify -
```

## What It Checks

- Proof format and structural integrity
- Base64 encoding validity
- Minimum proof size constraints
- Circuit hash presence
- Gate definitions present
- Public inputs completeness

For full cryptographic verification, submit proofs to the Minerva API at `https://zkesg.com/api/v1/proofs/verify` or use the web verifier at `zkesg.com/verify`.

## Output

```
✅ proof.json — Valid (684 bytes, 3 gates, verified in 1.2ms)
❌ bad-proof.json — Invalid: missing circuit hash
```

With `--json`:
```json
{
  "file": "proof.json",
  "valid": true,
  "proof_size": 684,
  "gates": 3,
  "elapsed_ms": 1.2
}
```

## License

Proprietary — see [LICENSE](./LICENSE)

Copyright (c) 2025-2026 Abdolah Pouriliaee / Digital Forge Studios
