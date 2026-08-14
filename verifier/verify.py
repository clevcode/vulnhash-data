#!/usr/bin/env python3
"""Verify VulnHash receipts, batch manifests, and optional Base state."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

MANIFEST_SCHEMA = "vulnhash-anchor-batch-v1"
RECEIPT_SCHEMA = "vulnhash-submission-receipt-v1"
CERTIFIED_HASH_VERSION = "vulnhash-leaf-v1"
CERTIFIED_HASH_FORMAT = (
    'sha256(0x00 || "vulnhash-leaf-v1\\n" || submission_id || "\\n" || '
    'hash || "\\n" || submitted_at_unix || "\\n" || user_id || "\\n" || username)'
)
TREE_RULES = {
    "certified_hash_version": CERTIFIED_HASH_VERSION,
    "node_hash_algorithm": "sha256",
    "internal_node_prefix": "01",
    "padding": "duplicate-last-to-power-of-two-minimum-two",
    "minimum_width": 2,
}
ANCHORED_EVENT = "Anchored(bytes32,uint256,uint256)"
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HEX_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
HEX_TX = re.compile(r"^0x[0-9a-f]{64}$")
RFC3339_UTC = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$"
)


class VerificationError(ValueError):
    """Evidence did not satisfy a required invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"read {path}: {exc}") from exc
    require(type(value) is dict, f"{path} must contain a JSON object")
    return value


def canonical_utc(value: Any, name: str, *, seconds_only: bool = False) -> tuple[int, int]:
    require(type(value) is str, f"{name} must be a string")
    match = RFC3339_UTC.fullmatch(value)
    require(match is not None, f"{name} is not canonical UTC RFC3339")
    fraction = match.group(2)
    require(not seconds_only or fraction is None, f"{name} must have exact second precision")
    try:
        parsed = dt.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise VerificationError(f"invalid {name}: {exc}") from exc
    nanos = int((fraction or "0").ljust(9, "0"))
    return int(parsed.timestamp()), nanos


def require_int(value: Any, name: str, *, minimum: int | None = None) -> int:
    require(type(value) is int, f"{name} must be an integer")
    if minimum is not None:
        require(value >= minimum, f"{name} must be at least {minimum}")
    return value


def merkle_root(leaves: list[str]) -> str:
    require(len(leaves) > 0, "manifest must contain at least one leaf")
    layer = [bytes.fromhex(leaf) for leaf in leaves]
    if len(layer) == 1:
        layer.append(layer[-1])
    while len(layer) & (len(layer) - 1):
        layer.append(layer[-1])
    while len(layer) > 1:
        layer = [
            hashlib.sha256(b"\x01" + layer[i] + layer[i + 1]).digest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0].hex()


def load_deployments(path: Path) -> list[dict[str, Any]]:
    registry = load_json(path)
    require(
        registry.get("schema") == "vulnhash-contract-deployments-v1",
        "unsupported contract deployment registry",
    )
    deployments = registry.get("deployments")
    require(type(deployments) is list and deployments, "deployment registry is empty")
    for deployment in deployments:
        require(type(deployment) is dict, "deployment entry must be an object")
        require(HEX_ADDRESS.fullmatch(deployment.get("contract", "")) is not None,
                "deployment has an invalid contract address")
        require(HEX_ADDRESS.fullmatch(deployment.get("owner", "")) is not None,
                "deployment has an invalid owner address")
        require(HEX_32.fullmatch(deployment.get("runtime_bytecode_sha256", "")) is not None,
                "deployment has an invalid runtime bytecode digest")
        require(re.fullmatch(r"0x[0-9a-f]{8}", deployment.get("anchor_selector", "")) is not None,
                "deployment has an invalid anchor selector")
        require(re.fullmatch(r"0x[0-9a-f]{8}", deployment.get("verify_selector", "")) is not None,
                "deployment has an invalid verify selector")
        require(HEX_TX.fullmatch(deployment.get("anchored_event_topic", "")) is not None,
                "deployment has an invalid Anchored event topic")
    return deployments


def validate_manifest(
    manifest: dict[str, Any], deployments: list[dict[str, Any]]
) -> dict[str, Any]:
    require(manifest.get("schema") == MANIFEST_SCHEMA, "unsupported manifest schema")
    start = canonical_utc(manifest.get("period_start"), "period_start")
    end = canonical_utc(manifest.get("period_end"), "period_end")
    require(end >= start, "period_end precedes period_start")

    leaves = manifest.get("leaves")
    require(type(leaves) is list and leaves, "leaves must be a non-empty array")
    for index, leaf in enumerate(leaves):
        require(type(leaf) is str and HEX_32.fullmatch(leaf) is not None,
                f"leaf {index} is not a lowercase SHA-256 digest")
    require(len(leaves) == len(set(leaves)), "manifest contains duplicate leaves")
    require_int(manifest.get("leaf_count"), "leaf_count", minimum=1)
    require(manifest["leaf_count"] == len(leaves), "leaf_count does not match leaves")

    tree = manifest.get("tree")
    require(type(tree) is dict, "tree must be an object")
    for key, expected in TREE_RULES.items():
        require(tree.get(key) == expected, f"unexpected tree rule {key}")

    root = manifest.get("merkle_root")
    require(type(root) is str and HEX_32.fullmatch(root) is not None,
            "merkle_root is not a lowercase SHA-256 digest")
    require(merkle_root(leaves) == root, "Merkle root mismatch")

    chain = manifest.get("chain_anchor")
    require(type(chain) is dict, "chain_anchor must be an object")
    require(chain.get("network") == "base-mainnet", "chain anchor is not Base mainnet")
    require(chain.get("chain_id") == 8453, "chain anchor does not use chain ID 8453")
    require(HEX_ADDRESS.fullmatch(chain.get("contract", "")) is not None,
            "chain anchor has an invalid contract address")
    require(HEX_TX.fullmatch(chain.get("transaction_hash", "")) is not None,
            "chain anchor has an invalid transaction hash")
    require_int(chain.get("block_number"), "block_number", minimum=1)
    require(chain.get("receipt_success") is True, "chain receipt is not successful")
    require_int(chain.get("anchored_at_unix"), "anchored_at_unix", minimum=1)
    require(chain.get("event") == ANCHORED_EVENT, "unexpected anchor event")

    matches = [
        deployment
        for deployment in deployments
        if deployment.get("network") == chain["network"]
        and deployment.get("chain_id") == chain["chain_id"]
        and deployment.get("contract") == chain["contract"]
    ]
    require(len(matches) == 1, "manifest contract is not uniquely listed in deployments.json")
    return matches[0]


def certified_hash(receipt: dict[str, Any]) -> str:
    data = (
        f"{CERTIFIED_HASH_VERSION}\n"
        f"{receipt['submission_id']}\n"
        f"{receipt['document_hash']}\n"
        f"{receipt['submitted_at_unix']}\n"
        f"{receipt['user_id']}\n"
        f"{receipt['username']}"
    ).encode("utf-8")
    return hashlib.sha256(b"\x00" + data).hexdigest()


def validate_receipt(
    receipt: dict[str, Any], manifest: dict[str, Any], report: Path | None = None
) -> str:
    require(receipt.get("schema") == RECEIPT_SCHEMA, "unsupported receipt schema")
    require(receipt.get("certified_hash_version") == CERTIFIED_HASH_VERSION,
            "unsupported certified hash version")
    require(receipt.get("certified_hash_format") == CERTIFIED_HASH_FORMAT,
            "certified hash format mismatch")
    require(receipt.get("digest_algorithm") == "sha256", "unsupported document digest")
    for field in ("submission_id", "user_id"):
        value = receipt.get(field)
        require(type(value) is str, f"{field} must be a string")
        try:
            uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise VerificationError(f"invalid {field}") from exc
    document_hash = receipt.get("document_hash")
    require(type(document_hash) is str and HEX_32.fullmatch(document_hash) is not None,
            "document_hash is not a lowercase SHA-256 digest")
    submitted = canonical_utc(receipt.get("submitted_at"), "submitted_at", seconds_only=True)
    submitted_unix = require_int(receipt.get("submitted_at_unix"), "submitted_at_unix")
    require(submitted[0] == submitted_unix, "submitted_at does not match submitted_at_unix")
    require(type(receipt.get("username")) is str and receipt["username"], "username is empty")

    computed = certified_hash(receipt)
    claimed = receipt.get("certified_hash")
    require(type(claimed) is str and HEX_32.fullmatch(claimed) is not None,
            "certified_hash is not a lowercase SHA-256 digest")
    require(claimed == computed, "certified hash mismatch")
    require(manifest["leaves"].count(computed) == 1,
            "receipt's certified hash is not uniquely present in the manifest")

    if report is not None:
        try:
            report_hash = hashlib.sha256(report.read_bytes()).hexdigest()
        except OSError as exc:
            raise VerificationError(f"read {report}: {exc}") from exc
        require(report_hash == document_hash, "report bytes do not match document_hash")
    return computed


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json", "user-agent": "vulnhash-data-verifier/1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except Exception as exc:  # urllib exposes several transport-specific errors
        raise VerificationError(f"Base RPC {method} failed: {exc}") from exc
    require(type(payload) is dict, f"Base RPC {method} returned a non-object")
    require("error" not in payload, f"Base RPC {method} error: {payload.get('error')}")
    require("result" in payload, f"Base RPC {method} omitted result")
    return payload["result"]


def hex_int(value: Any, name: str) -> int:
    require(type(value) is str and re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None,
            f"{name} is not a hexadecimal integer")
    return int(value, 16)


def lower_string(value: Any, name: str) -> str:
    require(type(value) is str, f"{name} must be a string")
    return value.lower()


def verify_chain(
    manifest: dict[str, Any],
    deployment: dict[str, Any],
    call: Callable[[str, list[Any]], Any],
    confirmations: int,
) -> int:
    chain = manifest["chain_anchor"]
    root = manifest["merkle_root"]
    contract = chain["contract"]
    tx_hash = chain["transaction_hash"]

    require(hex_int(call("eth_chainId", []), "eth_chainId") == chain["chain_id"],
            "RPC chain ID mismatch")
    transaction = call("eth_getTransactionByHash", [tx_hash])
    require(type(transaction) is dict, "anchor transaction was not found")
    require(lower_string(transaction.get("to"), "transaction recipient") == contract,
            "transaction targets wrong contract")
    if transaction.get("hash") is not None:
        require(lower_string(transaction["hash"], "transaction hash") == tx_hash,
                "transaction hash mismatch")
    require(hex_int(transaction.get("blockNumber"), "transaction block") == chain["block_number"],
            "transaction block mismatch")
    calldata = transaction.get("input", transaction.get("data"))
    require(type(calldata) is str and re.fullmatch(r"0x[0-9a-fA-F]+", calldata) is not None,
            "transaction calldata is malformed")
    calldata = calldata.lower()
    require(len(calldata) == 138, "anchor calldata has the wrong length")
    require(calldata[:10] == deployment["anchor_selector"], "anchor selector mismatch")
    require(calldata[10:74] == root, "anchor calldata root mismatch")
    require(int(calldata[74:138], 16) == manifest["leaf_count"], "anchor calldata leaf count mismatch")

    receipt = call("eth_getTransactionReceipt", [tx_hash])
    require(type(receipt) is dict, "anchor receipt was not found")
    require(hex_int(receipt.get("status"), "receipt status") == 1, "anchor transaction reverted")
    require(lower_string(receipt.get("to"), "receipt recipient") == contract,
            "receipt targets wrong contract")
    require(hex_int(receipt.get("blockNumber"), "receipt block") == chain["block_number"],
            "receipt block mismatch")
    if receipt.get("transactionHash") is not None:
        require(lower_string(receipt["transactionHash"], "receipt transaction hash") == tx_hash,
                "receipt transaction hash mismatch")

    matching_logs = [
        log
        for log in receipt.get("logs", [])
        if type(log) is dict
        and type(log.get("address")) is str
        and log["address"].lower() == contract
        and type(log.get("topics")) is list
        and log["topics"]
        and type(log["topics"][0]) is str
        and log["topics"][0].lower() == deployment["anchored_event_topic"]
    ]
    require(len(matching_logs) == 1, "receipt does not contain exactly one Anchored event")
    event = matching_logs[0]
    require(len(event["topics"]) == 2, "Anchored event has unexpected indexed fields")
    require(lower_string(event["topics"][1], "Anchored event root") == "0x" + root,
            "Anchored event root mismatch")
    event_data = event.get("data", "")
    require(type(event_data) is str and re.fullmatch(r"0x[0-9a-fA-F]{128}", event_data) is not None,
            "Anchored event data is malformed")
    require(int(event_data[2:66], 16) == manifest["leaf_count"], "Anchored event leaf count mismatch")
    require(int(event_data[66:130], 16) == chain["anchored_at_unix"],
            "Anchored event timestamp mismatch")

    result = call("eth_call", [{"to": contract, "data": deployment["verify_selector"] + root}, "latest"])
    require(type(result) is str and re.fullmatch(r"0x[0-9a-fA-F]{128}", result) is not None,
            "verify(root) returned malformed data")
    require(int(result[2:66], 16) == 1, "contract verify(root) reports absent")
    require(int(result[66:130], 16) == chain["anchored_at_unix"],
            "contract timestamp mismatch")

    runtime = call("eth_getCode", [contract, "latest"])
    require(type(runtime) is str and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", runtime) is not None,
            "contract runtime bytecode is malformed")
    runtime_hash = hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest()
    require(runtime_hash == deployment["runtime_bytecode_sha256"],
            "contract runtime bytecode is not the registered deployment")

    latest = hex_int(call("eth_blockNumber", []), "latest block")
    depth = latest - chain["block_number"] + 1
    require(depth >= confirmations,
            f"anchor has {depth} confirmations; {confirmations} required")
    return depth


def default_deployments_path() -> Path:
    return Path(__file__).resolve().parents[1] / "contracts" / "deployments.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="batch manifest JSON")
    parser.add_argument("--receipt", type=Path, help="private submission receipt JSON")
    parser.add_argument("--report", type=Path, help="exact report bytes; requires --receipt")
    parser.add_argument("--leaf", help="certified hash whose inclusion must be checked")
    parser.add_argument("--rpc-url", help="explicit Base JSON-RPC endpoint for online checks")
    parser.add_argument("--confirmations", type=int, default=12)
    parser.add_argument("--deployments", type=Path, default=default_deployments_path())
    args = parser.parse_args(argv)

    try:
        require(args.report is None or args.receipt is not None, "--report requires --receipt")
        require(args.confirmations >= 1, "--confirmations must be positive")
        manifest = load_json(args.manifest)
        deployments = load_deployments(args.deployments)
        deployment = validate_manifest(manifest, deployments)
        print(f"manifest: valid ({manifest['leaf_count']} leaves, root {manifest['merkle_root']})")
        print(f"deployment: recognized ({manifest['chain_anchor']['contract']})")

        if args.leaf is not None:
            require(HEX_32.fullmatch(args.leaf) is not None,
                    "--leaf must be a lowercase SHA-256 digest")
            require(manifest["leaves"].count(args.leaf) == 1,
                    "--leaf is not uniquely present in the manifest")
            print("leaf: included")

        if args.receipt is not None:
            receipt = load_json(args.receipt)
            leaf = validate_receipt(receipt, manifest, args.report)
            if args.leaf is not None:
                require(args.leaf == leaf, "--leaf does not match receipt")
            print("receipt: valid and included")
            print("report: valid" if args.report is not None else "report: not supplied")

        if args.rpc_url:
            depth = verify_chain(
                manifest,
                deployment,
                lambda method, params: rpc_call(args.rpc_url, method, params),
                args.confirmations,
            )
            print(f"chain: valid ({depth} confirmations)")
        else:
            print("chain: not queried (offline validation only)")
        return 0
    except VerificationError as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
