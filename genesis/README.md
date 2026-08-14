# Production genesis evidence

`VULNHASH-GENESIS-v1.md` is a deliberate public operator submission used to
exercise the production evidence path end to end. Unlike researcher reports,
both its exact document and private-receipt fields are intentionally public.
The operator invoked the server's explicit `-anchor-now` mode after submission,
so this test used the normal durable sealing and publication state machine but
deliberately bypassed the one-hour scheduling delay. Production remains
configured for the ordinary one-hour interval.

| Field | Value |
| --- | --- |
| Document SHA-256 | `662e4d8dfebc7fe2b730b10ab923ce631408ed2c5d4c2710934c27528baf1255` |
| Certified hash | `1f3fabbaf9b447fbb0d5973955cc87f5fbb7273a32efa05f90d4a7d4d2d79aef` |
| Merkle root | `ea3fb90494d1af0354fd3129aa48c67a3ddafb3f6acc12ea3ae92487e25cc08a` |
| Base contract | `0x86e306175605ad8a9966cf226e7f780052b8efd3` |
| Base transaction | `0x1a5f21fc6c7463ecb361a8d071a230fd83271af5690a9b483ff0cb24c01d0bb2` |
| Base block | `49974047` |
| Batch creation commit | `d40e60427f0ad749eea3132a3a3beb0d882f6de9` |

Verify the exact document, receipt, complete batch, deployment registry, and
live Base state with the dependency-free verifier:

```shell
python3 verifier/verify.py \
  batches/ea3fb90494d1af0354fd3129aa48c67a3ddafb3f6acc12ea3ae92487e25cc08a.json \
  --receipt genesis/VULNHASH-GENESIS-v1.receipt.json \
  --report genesis/VULNHASH-GENESIS-v1.md \
  --rpc-url https://your-base-rpc.example
```

Omit `--rpc-url` for a fully offline verification of every layer through the
Merkle root. The live chain check is read-only and may use a local node or a
separately Tor-routed Base endpoint.
