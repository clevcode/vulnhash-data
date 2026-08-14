import copy
import datetime as dt
import hashlib
import tempfile
import unittest
import uuid
from pathlib import Path

from verifier.verify import (
    ANCHORED_EVENT,
    CERTIFIED_HASH_FORMAT,
    TREE_RULES,
    VerificationError,
    certified_hash,
    merkle_root,
    validate_manifest,
    validate_receipt,
    verify_chain,
)


CONTRACT = "0x" + "12" * 20
OWNER = "0x" + "34" * 20
TX_HASH = "0x" + "56" * 32
EVENT_TOPIC = "0x" + "78" * 32
RUNTIME = bytes.fromhex("6000")
ROOT_TIME = 1_765_800_000


def deployment():
    return {
        "network": "base-mainnet",
        "chain_id": 8453,
        "contract": CONTRACT,
        "owner": OWNER,
        "runtime_bytecode_sha256": hashlib.sha256(RUNTIME).hexdigest(),
        "anchor_selector": "0x8f5bae2e",
        "verify_selector": "0x75e36616",
        "anchored_event": ANCHORED_EVENT,
        "anchored_event_topic": EVENT_TOPIC,
    }


def manifest():
    leaves = ["11" * 32, "22" * 32, "33" * 32]
    return {
        "schema": "vulnhash-anchor-batch-v1",
        "period_start": "2026-08-14T12:00:00Z",
        "period_end": "2026-08-14T13:00:00.000000123Z",
        "leaf_count": len(leaves),
        "leaves": leaves,
        "merkle_root": merkle_root(leaves),
        "tree": dict(TREE_RULES),
        "chain_anchor": {
            "network": "base-mainnet",
            "chain_id": 8453,
            "contract": CONTRACT,
            "transaction_hash": TX_HASH,
            "block_number": 100,
            "receipt_success": True,
            "anchored_at_unix": ROOT_TIME,
            "event": ANCHORED_EVENT,
        },
    }


def receipt(report: bytes):
    value = {
        "schema": "vulnhash-submission-receipt-v1",
        "certified_hash_version": "vulnhash-leaf-v1",
        "certified_hash_format": CERTIFIED_HASH_FORMAT,
        "submission_id": str(uuid.UUID("11111111-1111-4111-8111-111111111111")),
        "digest_algorithm": "sha256",
        "document_hash": hashlib.sha256(report).hexdigest(),
        "submitted_at": "2026-08-14T12:00:00Z",
        "submitted_at_unix": int(
            dt.datetime(2026, 8, 14, 12, tzinfo=dt.timezone.utc).timestamp()
        ),
        "user_id": str(uuid.UUID("22222222-2222-4222-8222-222222222222")),
        "username": "researcher",
    }
    value["certified_hash"] = certified_hash(value)
    return value


class ManifestTests(unittest.TestCase):
    def test_valid_manifest(self):
        value = manifest()
        self.assertEqual(
            value["merkle_root"],
            "b830e7c9b9f8d3e70091a1e552847b7cb588c21309781df3b782ef2d26ccd18a",
        )
        self.assertEqual(validate_manifest(value, [deployment()]), deployment())

    def test_modified_leaf_and_order_fail(self):
        for changed in ("leaf", "order"):
            with self.subTest(changed=changed):
                value = manifest()
                if changed == "leaf":
                    value["leaves"][0] = "44" * 32
                else:
                    value["leaves"][0], value["leaves"][1] = (
                        value["leaves"][1],
                        value["leaves"][0],
                    )
                with self.assertRaises(VerificationError):
                    validate_manifest(value, [deployment()])

    def test_duplicate_leaf_fails_even_with_rebuilt_root(self):
        value = manifest()
        value["leaves"][1] = value["leaves"][0]
        value["merkle_root"] = merkle_root(value["leaves"])
        with self.assertRaises(VerificationError):
            validate_manifest(value, [deployment()])

    def test_unlisted_contract_fails(self):
        value = manifest()
        value["chain_anchor"]["contract"] = "0x" + "99" * 20
        with self.assertRaises(VerificationError):
            validate_manifest(value, [deployment()])


class ReceiptTests(unittest.TestCase):
    def test_certified_hash_matches_go_and_rust_fixture(self):
        value = {
            "submission_id": "11111111-1111-4111-8111-111111111111",
            "document_hash": "ab" * 32,
            "submitted_at_unix": 1_786_710_896,
            "user_id": "22222222-2222-4222-8222-222222222222",
            "username": "researcher",
        }
        self.assertEqual(
            certified_hash(value),
            "8fe6c8321bd99c66290cc7720860c140489d3321d2730f111d7c1c7b18aa916f",
        )

    def test_report_receipt_and_manifest(self):
        report = b"proof bytes\n"
        value = receipt(report)
        batch = manifest()
        batch["leaves"][0] = value["certified_hash"]
        batch["merkle_root"] = merkle_root(batch["leaves"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PROOF.md"
            path.write_bytes(report)
            self.assertEqual(validate_receipt(value, batch, path), value["certified_hash"])

    def test_modified_report_fails(self):
        report = b"proof bytes\n"
        value = receipt(report)
        batch = manifest()
        batch["leaves"][0] = value["certified_hash"]
        batch["merkle_root"] = merkle_root(batch["leaves"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PROOF.md"
            path.write_bytes(b"changed\n")
            with self.assertRaises(VerificationError):
                validate_receipt(value, batch, path)


class ChainTests(unittest.TestCase):
    def responses(self, batch):
        root = batch["merkle_root"]
        count = batch["leaf_count"]
        calldata = "0x8f5bae2e" + root + f"{count:064x}"
        event_data = "0x" + f"{count:064x}" + f"{ROOT_TIME:064x}"
        verify_result = "0x" + f"{1:064x}" + f"{ROOT_TIME:064x}"
        return {
            "eth_chainId": "0x2105",
            "eth_getTransactionByHash": {
                "hash": TX_HASH,
                "to": CONTRACT,
                "blockNumber": "0x64",
                "input": calldata,
            },
            "eth_getTransactionReceipt": {
                "transactionHash": TX_HASH,
                "to": CONTRACT,
                "blockNumber": "0x64",
                "status": "0x1",
                "logs": [
                    {
                        "address": CONTRACT,
                        "topics": [EVENT_TOPIC, "0x" + root],
                        "data": event_data,
                    }
                ],
            },
            "eth_call": verify_result,
            "eth_getCode": "0x" + RUNTIME.hex(),
            "eth_blockNumber": "0x70",
        }

    def test_complete_chain_validation(self):
        batch = manifest()
        responses = self.responses(batch)
        depth = verify_chain(batch, deployment(), lambda method, _params: responses[method], 12)
        self.assertEqual(depth, 13)

    def test_wrong_event_count_fails(self):
        batch = manifest()
        responses = self.responses(batch)
        responses = copy.deepcopy(responses)
        responses["eth_getTransactionReceipt"]["logs"][0]["data"] = (
            "0x" + f"{99:064x}" + f"{ROOT_TIME:064x}"
        )
        with self.assertRaises(VerificationError):
            verify_chain(batch, deployment(), lambda method, _params: responses[method], 12)


if __name__ == "__main__":
    unittest.main()
