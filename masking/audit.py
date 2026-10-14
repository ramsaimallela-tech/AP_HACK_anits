"""Tamper-evident audit log with SHA3-256 hash chaining and ML-DSA-65 post-quantum digital signatures."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from .pqc import get_pqc_manager


GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def normalize_sql(sql: str) -> str:
    """Replaces literals with '?' so raw PII in predicates never appears in audit logs."""
    # Replace single-quoted strings
    s = re.sub(r"'[^']*'", "?", sql)
    # Replace numbers
    s = re.sub(r"\b\d+\b", "?", s)
    return s.strip()


@dataclass
class AuditRecord:
    id: int
    ts: str
    user: str
    role: str
    query_id: str
    sql_normalized: str
    masked_columns: list[dict[str, str]]
    row_count: int
    elapsed_ms: float
    decision: str
    prev_hash: str
    entry_hash: str
    sig_alg: str
    signature: str
    key_id: str


class AuditLog:
    """Manages the append-only, tamper-evident post-quantum signed audit chain."""

    def __init__(self, log_path: str = "data/audit_chain.jsonl"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        self.pqc = get_pqc_manager()

    def _get_last_entry(self) -> AuditRecord | None:
        if not os.path.exists(self.log_path):
            return None
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if not lines:
                return None
            data = json.loads(lines[-1])
            return AuditRecord(**data)

    def append(
        self,
        user: str,
        role: str,
        sql: str,
        masked_columns: list[dict[str, str]],
        row_count: int,
        elapsed_ms: float,
        decision: str = "allowed",
        query_id: str | None = None,
    ) -> AuditRecord:
        last = self._get_last_entry()
        next_id = (last.id + 1) if last else 1
        prev_hash = last.entry_hash if last else GENESIS_HASH

        q_id = query_id or str(uuid.uuid4())
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        norm_sql = normalize_sql(sql)

        # Canonical representation for hashing
        payload = {
            "id": next_id,
            "ts": ts,
            "user": user,
            "role": role,
            "query_id": q_id,
            "sql_normalized": norm_sql,
            "masked_columns": masked_columns,
            "row_count": row_count,
            "elapsed_ms": round(elapsed_ms, 2),
            "decision": decision,
            "prev_hash": prev_hash,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha3_256(canonical_bytes).hexdigest()

        # Sign with ML-DSA-65 post-quantum signature
        sig_info = self.pqc.sign(entry_hash)

        record = AuditRecord(
            id=next_id,
            ts=ts,
            user=user,
            role=role,
            query_id=q_id,
            sql_normalized=norm_sql,
            masked_columns=masked_columns,
            row_count=row_count,
            elapsed_ms=round(elapsed_ms, 2),
            decision=decision,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            sig_alg=sig_info["sig_alg"],
            signature=sig_info["signature"],
            key_id=sig_info["key_id"],
        )

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(record)) + "\n")

        return record

    def get_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        if not os.path.exists(self.log_path):
            return []
        records = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        return records[-limit:][::-1]

    def verify_chain(self) -> dict[str, Any]:
        """Walks the entire audit log from id 1 to N, verifying:

        1. Sequential IDs
        2. Hash-chain linkage (prev_hash matches preceding entry_hash)
        3. Recalculated SHA3-256 entry_hash
        4. ML-DSA-65 Post-Quantum digital signature validity
        """
        if not os.path.exists(self.log_path):
            return {"valid": True, "total_verified": 0, "status": "No audit entries recorded yet."}

        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        if not entries:
            return {"valid": True, "total_verified": 0, "status": "Empty log."}

        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(entries):
            # Check ID
            expected_id = idx + 1
            if entry.get("id") != expected_id:
                return {
                    "valid": False,
                    "total_verified": idx,
                    "broken_at_id": entry.get("id"),
                    "status": f"Invalid ID sequence: Expected {expected_id}, got {entry.get('id')}",
                }

            # Check prev_hash
            if entry.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "total_verified": idx,
                    "broken_at_id": entry.get("id"),
                    "status": f"Hash chain broken at row #{entry.get('id')}: prev_hash mismatch",
                }

            # Recalculate entry_hash
            payload = {
                "id": entry["id"],
                "ts": entry["ts"],
                "user": entry["user"],
                "role": entry["role"],
                "query_id": entry["query_id"],
                "sql_normalized": entry["sql_normalized"],
                "masked_columns": entry["masked_columns"],
                "row_count": entry["row_count"],
                "elapsed_ms": entry["elapsed_ms"],
                "decision": entry["decision"],
                "prev_hash": entry["prev_hash"],
            }
            canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            calculated_hash = hashlib.sha3_256(canonical_bytes).hexdigest()

            if calculated_hash != entry.get("entry_hash"):
                return {
                    "valid": False,
                    "total_verified": idx,
                    "broken_at_id": entry.get("id"),
                    "status": f"Tampered data detected at row #{entry.get('id')}: calculated hash does not match recorded hash",
                }

            # Verify ML-DSA-65 post-quantum signature
            sig_valid = self.pqc.verify(entry["entry_hash"], entry["signature"])
            if not sig_valid:
                return {
                    "valid": False,
                    "total_verified": idx,
                    "broken_at_id": entry.get("id"),
                    "status": f"PQC Signature verification failed at row #{entry.get('id')}: ML-DSA-65 signature is invalid or forged!",
                }

            expected_prev = entry["entry_hash"]

        return {
            "valid": True,
            "total_verified": len(entries),
            "status": f"All {len(entries)} audit rows successfully verified against SHA3-256 chain and ML-DSA-65 post-quantum signatures.",
        }
