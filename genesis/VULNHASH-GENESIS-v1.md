# VulnHash production genesis

This is the deliberate first production submission to VulnHash. It is a public
operator-owned test record, not a vulnerability report or a priority claim.

- Service: https://vulnhash.com
- Operator: ClevCode Ltd, Cyprus (HE 418130; VAT CY10418130L)
- Evidence repository: https://github.com/clevcode/vulnhash-data
- Network: Base mainnet (chain ID 8453)
- Canonical contract: `0x86e306175605ad8a9966cf226e7f780052b8efd3`
- Contract deployment transaction: `0x6079bfb2069b2e80ee15be6ef407f0b1842ca1bc4f2f5a5409ade85ce8ac91fc`
- Anchor wallet and contract owner: `0x8050e67be8b1e185d97291a15420f498b3d433fb`

Its purpose is to exercise the normal authenticated submission, private receipt,
hourly batch, Base anchoring, GitHub publication, locator, and independent
verification paths end to end. The resulting receipt is intentionally published
beside this document as a worked example; this does not change the privacy model
for researcher submissions.

The submitted document hash is SHA-256 over the exact UTF-8 bytes of this file,
including its final newline. The receipt and batch manifest provide the remaining
values needed to reconstruct the certified hash and verify the Base anchor.
