# VulnHash public evidence data

This is the public, append-only data repository for VulnHash anchor batches.
The hosted service is operated by ClevCode Ltd, Cyprus. The server source is
not stored here.

Every `batches/<merkle-root>.json` file contains the complete ordered list of
certified hashes in one batch and the Base-mainnet transaction that anchored
its Merkle root. A commit-pinned copy of that file is sufficient to rebuild
the root without the VulnHash server or database.

Researcher submissions remain private: this repository does not contain their
receipts, document hashes, submission UUIDs, user IDs, usernames, report
contents, attachments, or authentication data. Researchers must privately
retain both their exact report and `receipt.json`. The deliberately public
operator-owned genesis record under `genesis/` is the sole initial exception;
its document and receipt are published to provide a complete worked example.

## Verification

Validate one manifest without making a network request:

```shell
python3 verifier/verify.py batches/<merkle-root>.json
```

Validate a report, private receipt, and manifest together:

```shell
python3 verifier/verify.py batches/<merkle-root>.json \
  --receipt /private/path/receipt.json \
  --report /private/path/PROOF.md
```

Independently query Base as well:

```shell
python3 verifier/verify.py batches/<merkle-root>.json \
  --receipt /private/path/receipt.json \
  --report /private/path/PROOF.md \
  --rpc-url https://your-base-rpc.example
```

The RPC URL is supplied explicitly so the verifier never makes an unexpected
network request. It may point at a local node or a separately Tor-routed
endpoint.

The verifier checks the manifest schema and tree rules, rebuilds the Merkle
root, optionally reconstructs the certified hash from the private receipt and
report, and optionally validates the Base transaction, receipt, event,
contract state, runtime bytecode, and confirmations.

GitHub is the public distribution and mirroring layer, not the timestamp
authority. Base establishes the public upper time bound for the root. Earlier
submission and batch-period timestamps were recorded by VulnHash and only
committed later.

## Layout

- `batches/` — create-only batch manifests named by Merkle root
- `schemas/` — versioned JSON schemas for public manifests and private receipts
- `contracts/` — deployed contract source, ABI, and Base deployment registry
- `genesis/` — deliberate public production-genesis document and receipt
- `verifier/` — dependency-free Python verifier
- `MIRRORING.md` — independent mirroring and integrity-check instructions

## Append-only policy

Files below `batches/` are created once and are not amended in place. VulnHash
locators identify the exact creation commit rather than `main`. A conflicting
existing path is treated as an integrity incident. Any repository rewrite,
deletion, or retention-policy change must be publicly documented as an
incident or policy change; independent mirrors remain valid evidence.

The `main` branch rejects force pushes and deletion, enforces linear history,
and applies those rules to repository administrators. These controls support
the policy but do not replace independent mirrors: an administrator could
still change repository settings or remove the repository through GitHub.

## Licensing

Batch manifests and other factual evidence data are offered under CC0 1.0
Universal; see `DATA-LICENSE.md`. Verifier code, schemas, contract source, and
documentation are licensed under the MIT License; see `LICENSE`.

## Operator

VulnHash is a ClevCode project. The hosted service is operated by ClevCode Ltd,
Cyprus, company registration HE 418130, VAT CY10418130L.
