"""Automated PII scanner with multi-heuristic scoring, value-sampling detectors,

and support for live databases and custom uploaded datasets.
"""
from __future__ import annotations

import datetime
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

TAG_THRESHOLD = 0.55

# Sensitivities
TAG_HIGH = "PII_HIGH"
TAG_MEDIUM = "PII_MEDIUM"
TAG_FINANCIAL = "FINANCIAL_CONFIDENTIAL"
TAG_NON_SENSITIVE = "NON_SENSITIVE"

TAG_RANK = {
    TAG_NON_SENSITIVE: 0,
    TAG_MEDIUM: 1,
    TAG_FINANCIAL: 2,
    TAG_HIGH: 3,
}

# Regexes
EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")
SSN_RE = re.compile(r"^(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}$")
IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
CARD_CLEAN_RE = re.compile(r"[\s-]")


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", str(number))]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_mod97_ok(val: str) -> bool:
    s = re.sub(r"\s+", "", str(val).upper())
    if not IBAN_RE.fullmatch(s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - 55)
    return int(numeric) % 97 == 1


def parse_date_age(val: Any) -> bool:
    s = str(val).strip()
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            dt = datetime.datetime.strptime(s, fmt).date()
            today = datetime.date.today()
            age = (today - dt).days / 365.25
            return 0 <= age <= 120
        except ValueError:
            pass
    return False


def tokenize_name(name: str) -> list[str]:
    s1 = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    tokens = [t.lower() for t in re.split(r"[^a-zA-Z0-9]+", s1) if t]
    return tokens


@dataclass
class Detector:
    name: str
    tag: str
    strong_hints: list[str]
    weak_hints: list[str]
    value_only_ok: bool
    allowed_types: list[str] = field(default_factory=lambda: ["text"])
    has_value_check: bool = False

    def check_value(self, val: Any) -> bool:
        return False

    def match_name(self, col_name: str) -> tuple[float, str]:
        tokens = tokenize_name(col_name)
        joined_col = "".join(tokens)

        # Check strong hints
        for h in self.strong_hints:
            h_tokens = tokenize_name(h)
            h_joined = "".join(h_tokens)
            if h_joined == joined_col:
                return 0.60, f"column name exactly matches strong hint '{h}'"
            # contiguous subsequence
            for i in range(len(tokens) - len(h_tokens) + 1):
                if tokens[i : i + len(h_tokens)] == h_tokens:
                    return 0.60, f"column tokens contain strong hint '{h}'"

        # Check weak hints
        for w in self.weak_hints:
            if w in tokens:
                return 0.35, f"column tokens contain weak hint '{w}'"

        return 0.0, "no name match"


class CardDetector(Detector):
    def __init__(self):
        super().__init__(
            name="card",
            tag=TAG_HIGH,
            strong_hints=["card_number", "cc_number", "credit_card", "credit_card_number", "card_no", "pan"],
            weak_hints=["card", "cc"],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None or isinstance(val, (bool, int, float)):
            return False
        s = CARD_CLEAN_RE.sub("", str(val).strip())
        return s.isdigit() and 13 <= len(s) <= 19 and luhn_ok(s)


class SSNDetector(Detector):
    def __init__(self):
        super().__init__(
            name="ssn",
            tag=TAG_HIGH,
            strong_hints=["ssn", "social_security", "social_security_number", "national_id"],
            weak_hints=[],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None or isinstance(val, bool):
            return False
        s = str(val).strip()
        return bool(SSN_RE.match(s))


class PassportDetector(Detector):
    def __init__(self):
        super().__init__(
            name="passport",
            tag=TAG_HIGH,
            strong_hints=["passport", "passport_number", "passport_no"],
            weak_hints=[],
            value_only_ok=False,
            allowed_types=["text"],
            has_value_check=False,
        )


class EmailDetector(Detector):
    def __init__(self):
        super().__init__(
            name="email",
            tag=TAG_MEDIUM,
            strong_hints=["email", "e_mail", "email_address"],
            weak_hints=["mail"],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None:
            return False
        return bool(EMAIL_RE.match(str(val).strip()))


class PhoneDetector(Detector):
    def __init__(self):
        super().__init__(
            name="phone",
            tag=TAG_MEDIUM,
            strong_hints=["phone", "phone_number", "mobile", "cell", "telephone", "tel"],
            weak_hints=["contact"],
            value_only_ok=False,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None:
            return False
        digits = re.sub(r"\D", "", str(val))
        return 10 <= len(digits) <= 15


class DOBDetector(Detector):
    def __init__(self):
        super().__init__(
            name="dob",
            tag=TAG_MEDIUM,
            strong_hints=["dob", "date_of_birth", "birth_date", "birthdate", "birthday"],
            weak_hints=["birth"],
            value_only_ok=False,
            allowed_types=["date", "datetime", "text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        return parse_date_age(val)


class PersonNameDetector(Detector):
    def __init__(self):
        super().__init__(
            name="person_name",
            tag=TAG_MEDIUM,
            strong_hints=["first_name", "last_name", "full_name", "surname", "given_name", "family_name", "customer_name", "holder_name"],
            weak_hints=["name"],
            value_only_ok=False,
            allowed_types=["text"],
            has_value_check=False,
        )


class AddressDetector(Detector):
    def __init__(self):
        super().__init__(
            name="address",
            tag=TAG_MEDIUM,
            strong_hints=["address", "street", "street_address", "postal_code", "zip", "zip_code"],
            weak_hints=["addr"],
            value_only_ok=False,
            allowed_types=["text"],
            has_value_check=False,
        )


class IBANDetector(Detector):
    def __init__(self):
        super().__init__(
            name="iban",
            tag=TAG_FINANCIAL,
            strong_hints=["iban"],
            weak_hints=[],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        return iban_mod97_ok(val)


class AccountNumberDetector(Detector):
    def __init__(self):
        super().__init__(
            name="account_number",
            tag=TAG_FINANCIAL,
            strong_hints=["account_number", "account_no", "acct_no", "acct_number", "bank_account", "routing_number"],
            weak_hints=["acct"],
            value_only_ok=False,
            allowed_types=["text", "integer"],
            has_value_check=False,
        )


class BalanceDetector(Detector):
    def __init__(self):
        super().__init__(
            name="balance",
            tag=TAG_FINANCIAL,
            strong_hints=["balance", "account_balance", "bal", "salary", "income", "net_worth", "amt", "amt1", "amt2"],
            weak_hints=["amount", "total", "val", "fee", "cost", "price"],
            value_only_ok=False,
            allowed_types=["integer", "numeric"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        try:
            f = float(val)
            return -1_000_000 <= f <= 100_000_000
        except (ValueError, TypeError):
            return False


VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 6, 7, 8, 9, 0, 1, 2, 3, 4],
    [6, 7, 8, 9, 5, 1, 2, 3, 4, 0],
    [7, 8, 9, 5, 6, 2, 3, 4, 0, 1],
    [8, 9, 5, 6, 7, 3, 4, 0, 1, 2],
    [9, 5, 6, 7, 8, 4, 0, 1, 2, 3]
]
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def verhoeff_check(val: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", str(val))]
    if len(digits) != 12 or digits[0] in (0, 1):
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][item]]
    return c == 0


class AadhaarDetector(Detector):
    def __init__(self):
        super().__init__(
            name="aadhaar",
            tag=TAG_HIGH,
            strong_hints=["aadhaar", "aadhaar_number", "aadhar", "aadhar_number", "uidai"],
            weak_hints=["uid"],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None or isinstance(val, bool):
            return False
        s = re.sub(r"[\s-]", "", str(val).strip())
        return s.isdigit() and len(s) == 12 and verhoeff_check(s)


IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


class IPAddressDetector(Detector):
    def __init__(self):
        super().__init__(
            name="ip_address",
            tag=TAG_MEDIUM,
            strong_hints=["ip_address", "ip", "client_ip", "remote_ip", "user_ip"],
            weak_hints=["host"],
            value_only_ok=True,
            allowed_types=["text"],
            has_value_check=True,
        )

    def check_value(self, val: Any) -> bool:
        if val is None or isinstance(val, bool):
            return False
        return bool(IP_RE.match(str(val).strip()))


ALL_DETECTORS: list[Detector] = [
    SSNDetector(),
    CardDetector(),
    IBANDetector(),
    AadhaarDetector(),
    IPAddressDetector(),
    EmailDetector(),
    PhoneDetector(),
    DOBDetector(),
    PersonNameDetector(),
    AddressDetector(),
    AccountNumberDetector(),
    BalanceDetector(),
    PassportDetector(),
]


def classify_sql_type(sql_type: str) -> str:
    s = (sql_type or "").upper()
    if any(k in s for k in ("BOOL", "BOOLEAN")):
        return "boolean"
    if any(k in s for k in ("INT", "BIGINT", "TINYINT")):
        return "integer"
    if any(k in s for k in ("REAL", "FLOAT", "DOUBLE", "NUMERIC", "DECIMAL")):
        return "numeric"
    if "DATE" in s:
        return "date"
    if "TIME" in s:
        return "datetime"
    return "text"


@dataclass
class ColumnTag:
    table: str
    column: str
    sql_type: str
    detector: str
    tag: str
    confidence: float
    status: str = "auto"  # 'auto' or 'override'
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.table}.{self.column}"

    @property
    def data_type(self) -> str:
        return self.detector


def score_column(
    table: str,
    column: str,
    sql_type: str,
    samples: list[Any],
    type_cat: str | None = None,
) -> ColumnTag:
    if type_cat is None:
        type_cat = classify_sql_type(sql_type)

    # Decoy trap check: Boolean columns (e.g. ssn_verified) must never be tagged
    if type_cat == "boolean" or column.lower().endswith("_verified") or column.lower().startswith("is_"):
        return ColumnTag(
            table=table,
            column=column,
            sql_type=sql_type,
            detector="none",
            tag=TAG_NON_SENSITIVE,
            confidence=0.0,
            reasons=["Column is boolean flag / verification decoy."],
        )

    non_null_samples = [s for s in samples if s is not None and str(s).strip() != ""]

    best_detector: Detector | None = None
    best_conf = 0.0
    best_reasons: list[str] = []
    best_evidence: dict[str, Any] = {}

    for detector in ALL_DETECTORS:
        if type_cat not in detector.allowed_types:
            continue

        name_w, name_reason = detector.match_name(column)

        # Value checks
        val_w = 0.0
        val_ratio = None

        if detector.has_value_check:
            matches = sum(1 for val in non_null_samples if detector.check_value(val))
            if non_null_samples:
                val_ratio = matches / len(non_null_samples)

                # Contradicting evidence rule: only penalize if value check is intended and overwhelmingly fails
                if len(non_null_samples) >= 20 and val_ratio < 0.05 and name_w > 0:
                    name_w *= 0.3

                if val_ratio >= 0.5:
                    val_w = 0.95 * val_ratio
                else:
                    val_w = 0.5 * val_ratio

        if not detector.value_only_ok and name_w == 0.0:
            val_w = 0.0

        confidence = 1.0 - (1.0 - name_w) * (1.0 - val_w)

        if confidence > best_conf:
            best_conf = confidence
            best_detector = detector
            reasons = []
            if name_w > 0:
                reasons.append(name_reason)
            if val_ratio is not None and val_ratio > 0.4:
                reasons.append(f"{val_ratio:.0%} of sample rows matched {detector.name} format")
            best_reasons = reasons
            best_evidence = {
                "name_match": name_w > 0,
                "value_ratio": round(val_ratio, 2) if val_ratio is not None else None,
                "samples_count": len(samples),
                "type_category": type_cat,
            }

    if best_detector and round(best_conf, 4) >= TAG_THRESHOLD:
        tag = best_detector.tag
        det_name = best_detector.name
    else:
        tag = TAG_NON_SENSITIVE
        det_name = best_detector.name if best_detector else "none"
        if not best_reasons:
            best_reasons = ["No PII characteristics exceeded confidence threshold."]

    return ColumnTag(
        table=table,
        column=column,
        sql_type=sql_type,
        detector=det_name,
        tag=tag,
        confidence=round(best_conf, 3),
        reasons=best_reasons,
        evidence=best_evidence,
    )


def scan_backend(backend, sample_size: int = 100) -> list[ColumnTag]:
    tags: list[ColumnTag] = []
    for table in backend.list_tables():
        for column, sql_type in backend.list_columns(table):
            samples = backend.sample(table, column, sample_size)
            tag = score_column(table, column, sql_type, samples)
            tags.append(tag)
    return tags


def scan_dataframe(df, table_name: str = "uploaded_dataset", sample_size: int = 200) -> list[ColumnTag]:
    """Scans a Pandas DataFrame (e.g. from uploaded CSV/Excel)."""
    tags: list[ColumnTag] = []
    n = min(len(df), sample_size)
    sampled_df = df.sample(n=n, random_state=42) if len(df) > n else df

    for col in df.columns:
        samples = sampled_df[col].dropna().tolist()
        dtype_str = str(df[col].dtype)
        if "int" in dtype_str:
            type_cat = "integer"
        elif "float" in dtype_str:
            type_cat = "numeric"
        elif "bool" in dtype_str:
            type_cat = "boolean"
        elif "datetime" in dtype_str:
            type_cat = "datetime"
        else:
            type_cat = "text"

        tag = score_column(table_name, str(col), dtype_str, samples, type_cat=type_cat)
        tags.append(tag)
    return tags


def save_catalog(path: str, tags: list[ColumnTag]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(t) for t in tags], f, indent=2)


def load_catalog(path: str) -> list[ColumnTag]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [ColumnTag(**row) for row in json.load(f)]
