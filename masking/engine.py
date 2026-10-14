"""Dynamic masking engine with Quantum Entropy seeding and Post-Quantum Signed Auditing."""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.lineage import lineage

from . import scanner
from .audit import AuditLog, AuditRecord
from .maskers import action_for, apply_mask
from .pqc import get_pqc_manager
from .quantum_entropy import get_quantum_generator
from .scanner import TAG_NON_SENSITIVE, TAG_RANK, ColumnTag


class QueryRejected(ValueError):
    pass


@dataclass
class QueryResult:
    role: str
    columns: list[str]
    rows: list[list]
    column_report: list[dict[str, Any]]
    truncated: bool = False
    row_count: int = 0
    elapsed_ms: float = 0.0
    quantum_seed: str = ""
    audit_record: AuditRecord | None = None


def _flatten(sql: str) -> str:
    out, depth, quote = [], 0, None
    for ch in sql:
        if quote:
            out.append(" ")
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            out.append(" ")
        elif ch == "(":
            depth += 1
            out.append("(")
        elif ch == ")":
            depth = max(depth - 1, 0)
            out.append(")")
        else:
            out.append(ch if depth == 0 else " ")
    return "".join(out)


def select_items(sql: str) -> list[str] | None:
    flat = _flatten(sql)
    head = re.match(r"\s*select\b(\s+distinct\b)?", flat, re.I)
    if not head or re.search(r"\b(union|intersect|except)\b", flat, re.I):
        return None
    m_from = re.search(r"\bfrom\b", flat, re.I)
    end = m_from.start() if m_from else len(flat)
    items, last = [], head.end()
    for m in re.finditer(",", flat[head.end():end]):
        pos = head.end() + m.start()
        items.append(sql[last:pos])
        last = pos + 1
    items.append(sql[last:end])
    return [i.strip() for i in items]


BARE_COLUMN = re.compile(r'(?:\w+\.)?"?(\w+)"?(?:\s+(?:as\s+)?"?\w+"?)?', re.I)


class MaskingEngine:
    def __init__(
        self,
        backend,
        catalog_path: str = "data/pii_catalog.json",
        audit_path: str = "data/audit_chain.jsonl",
        secret: str | None = None,
        max_rows: int = 1000,
    ):
        self.backend = backend
        self.catalog_path = catalog_path
        self.max_rows = max_rows
        self.quantum = get_quantum_generator()
        self.pqc = get_pqc_manager()
        self.audit_log = AuditLog(log_path=audit_path)
        self.secret = secret
        self.tags: list[ColumnTag] = []
        self._lookup: dict[str, ColumnTag] = {}
        self.overrides: dict[str, str] = {}  # col_key -> override_tag

        if os.path.exists(catalog_path):
            self._set_tags(scanner.load_catalog(catalog_path))

    def get_effective_secret(self) -> str:
        if self.secret:
            return self.secret
        return self.quantum.get_current_seed_hex()

    def _set_tags(self, tags: list[ColumnTag]) -> None:
        self.tags = tags
        lookup: dict[str, ColumnTag] = {}
        for t in tags:
            # Check override
            if t.key in self.overrides:
                t.tag = self.overrides[t.key]
                t.status = "override"

            cur = lookup.get(t.column.lower())
            if cur is None or TAG_RANK.get(t.tag, 0) > TAG_RANK.get(cur.tag, 0):
                lookup[t.column.lower()] = t
        self._lookup = lookup

    def get_schema(self) -> dict[str, dict[str, str]]:
        if not hasattr(self, "_cached_schema") or self._cached_schema is None:
            schema = {}
            for table in self.backend.list_tables():
                schema[table] = {col: sql_type for col, sql_type in self.backend.list_columns(table)}
            self._cached_schema = schema
        return self._cached_schema

    def scan(self, sample_size: int = 200) -> list[ColumnTag]:
        self._cached_schema = None
        tags = scanner.scan_backend(self.backend, sample_size)
        scanner.save_catalog(self.catalog_path, tags)
        self._set_tags(tags)
        return tags

    def set_override(self, table: str, column: str, tag: str) -> None:
        key = f"{table}.{column}"
        self.overrides[key] = tag
        for t in self.tags:
            if t.key == key:
                t.tag = tag
                t.status = "override"
        self._set_tags(self.tags)
        scanner.save_catalog(self.catalog_path, self.tags)

    def remove_override(self, table: str, column: str) -> None:
        key = f"{table}.{column}"
        self.overrides.pop(key, None)
        self.scan()

    def _validate(self, sql: str) -> str:
        sql = (sql or "").strip().rstrip(";").strip()
        if not sql:
            raise QueryRejected("Empty query.")
        if ";" in _flatten(sql):
            raise QueryRejected("Only a single SQL statement is permitted.")
        if not re.match(r"^\s*(select|with)\b", sql, re.I):
            raise QueryRejected("Security violation: Only read-only SELECT or WITH statements are allowed.")
        # Reject hazardous keywords
        blocked = ["insert", "update", "delete", "drop", "alter", "create", "attach", "copy", "pragma", "call"]
        first_token = sql.split()[0].lower() if sql.split() else ""
        if any(b == first_token for b in blocked):
            raise QueryRejected(f"Prohibited operation: '{first_token}' statement is rejected.")
        return sql

    def _enforce_predicate_security(self, sql: str, role: str) -> None:
        """Blocks non-admin roles from filtering, ordering, or grouping on PII_HIGH columns."""
        if (role or "").strip().lower() == "admin":
            return
        try:
            parsed = sqlglot.parse_one(sql)
            if parsed:
                for clause_type in (exp.Where, exp.Order, exp.Group, exp.Having):
                    for clause in parsed.find_all(clause_type):
                        for col_node in clause.find_all(exp.Column):
                            col_name = col_node.name.lower()
                            tag_obj = self._lookup.get(col_name)
                            if tag_obj and tag_obj.tag == "PII_HIGH":
                                clause_name = clause_type.__name__.upper()
                                raise QueryRejected(
                                    f"Security policy violation: Role '{role}' is not permitted to use "
                                    f"PII_HIGH column '{col_node.name}' in {clause_name} clause."
                                )
        except QueryRejected:
            raise
        except Exception:
            for sensitive_name, tag_obj in self._lookup.items():
                if tag_obj.tag == "PII_HIGH":
                    pattern = rf"\b(where|order\s+by|group\s+by|having)\b[^;]*\b{re.escape(sensitive_name)}\b"
                    if re.search(pattern, sql, re.IGNORECASE):
                        raise QueryRejected(
                            f"Security policy violation: Role '{role}' is not permitted to use "
                            f"PII_HIGH column '{sensitive_name}' in predicate/ordering."
                        )

    def _trace_lineage_tag(self, col_name: str, sql: str) -> tuple[ColumnTag | None, str | None]:
        try:
            schema = self.get_schema()
            node = lineage(col_name, sql, schema=schema)
            for n in node.walk():
                target_col = n.name.split(".")[-1].lower()
                if target_col in self._lookup:
                    hit = self._lookup[target_col]
                    if hit.tag != TAG_NON_SENSITIVE:
                        return hit, "sqlglot_lineage"
        except Exception:
            pass
        return None, None

    def _source_tag(self, name: str, expr: str | None, sql: str | None = None) -> tuple[ColumnTag | None, str | None]:
        if expr is not None and re.match(r"count\s*\(", expr, re.I):
            return None, None

        # 1. Try sqlglot lineage
        if sql:
            lin_hit, lin_how = self._trace_lineage_tag(name, sql)
            if lin_hit is not None:
                return lin_hit, lin_how

        # 2. Expression token match
        if expr is not None:
            cleaned = re.sub(r"'[^']*'", "", expr)
            hits = [self._lookup[i.lower()] for i in re.findall(r"[A-Za-z_]\w*", cleaned) if i.lower() in self._lookup]
            if not hits:
                return None, None
            bare = BARE_COLUMN.fullmatch(expr.strip())
            if bare and len(hits) == 1:
                return hits[0], "column"
            return max(hits, key=lambda t: TAG_RANK.get(t.tag, 0)), "expression"

        # 3. Column name match
        hit = self._lookup.get(name.lower())
        return (hit, "name") if hit else (None, None)

    def query(self, role: str, sql: str, params: tuple = (), user: str = "user") -> QueryResult:
        t0 = time.time()
        role_clean = (role or "analyst").lower()

        try:
            sql = self._validate(sql)
            self._enforce_predicate_security(sql, role_clean)
            cols, rows, truncated = self.backend.execute_readonly(sql, params, self.max_rows)
        except Exception as exc:
            elapsed = (time.time() - t0) * 1000
            self.audit_log.append(
                user=user,
                role=role_clean,
                sql=sql,
                masked_columns=[],
                row_count=0,
                elapsed_ms=elapsed,
                decision="error" if not isinstance(exc, QueryRejected) else "rejected",
            )
            raise

        items = select_items(sql)
        use_items = bool(items) and len(items) == len(cols) and not any(i == "*" or i.endswith(".*") for i in items)

        report = []
        plans = []
        effective_secret = self.get_effective_secret()

        for i, name in enumerate(cols):
            tag, how = self._source_tag(name, items[i] if use_items else None, sql=sql)
            if tag is not None and tag.tag != TAG_NON_SENSITIVE:
                dtype, tag_name = tag.data_type, tag.tag
            else:
                # Content fallback check on sample row values
                detected_by_content = False
                if rows:
                    sample_vals = [r[i] for r in rows[:15] if r[i] is not None and str(r[i]).strip()]
                    for det in (scanner.SSNDetector(), scanner.CardDetector(), scanner.EmailDetector(), scanner.IBANDetector(), scanner.AadhaarDetector(), scanner.IPAddressDetector()):
                        if any(det.check_value(sv) for sv in sample_vals):
                            dtype, tag_name = det.name, det.tag
                            how = "content_fallback"
                            detected_by_content = True
                            break
                if not detected_by_content:
                    dtype = "text"
                    tag_name = TAG_NON_SENSITIVE
                    how = "non_sensitive"

            action = action_for(role_clean, tag_name)
            plans.append((action, dtype))
            report.append({
                "column": name,
                "tag": tag_name,
                "data_type": dtype,
                "action": action,
                "detected_by": how,
            })

        masked_rows = [
            [apply_mask(v, plans[idx][0], plans[idx][1], effective_secret) for idx, v in enumerate(row)]
            for row in rows
        ]

        elapsed_ms = (time.time() - t0) * 1000
        masked_cols_summary = [
            {"column": r["column"], "tag": r["tag"], "action": r["action"]}
            for r in report if r["action"] != "none"
        ]

        audit_rec = self.audit_log.append(
            user=user,
            role=role_clean,
            sql=sql,
            masked_columns=masked_cols_summary,
            row_count=len(masked_rows),
            elapsed_ms=elapsed_ms,
            decision="allowed",
        )

        return QueryResult(
            role=role_clean,
            columns=cols,
            rows=masked_rows,
            column_report=report,
            truncated=truncated,
            row_count=len(masked_rows),
            elapsed_ms=round(elapsed_ms, 2),
            quantum_seed=effective_secret[:16] + "...",
            audit_record=audit_rec,
        )

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.audit_log.get_entries(limit)

    def verify_audit_trail(self) -> dict[str, Any]:
        return self.audit_log.verify_chain()
