"""CLI demo:  python cli.py scan | query --role support "SELECT ..." | compare "SELECT ..." """
import argparse
import os
import sys

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from seed import seed

DB = os.environ.get("BANK_DB", "data/bank.db")
ROLES = ["admin", "support", "analyst"]


def table(cols, rows, limit=15):
    rows = rows[:limit]
    widths = [max(len(str(c)), *(len(str(r[i])) for r in rows)) if rows else len(str(c)) for i, c in enumerate(cols)]
    line = "-+-".join("-" * w for w in widths)
    print(" | ".join(str(c).ljust(w) for c, w in zip(cols, widths)))
    print(line)
    for r in rows:
        print(" | ".join(str(v).ljust(w) for v, w in zip(r, widths)))


def main():
    ap = argparse.ArgumentParser(description="Smart Data Masking System")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="scan the database and tag PII columns")
    q = sub.add_parser("query", help="run a query as a role")
    q.add_argument("--role", default="support")
    q.add_argument("sql")
    c = sub.add_parser("compare", help="run a query as every role")
    c.add_argument("sql")
    args = ap.parse_args()

    if not os.path.exists(DB):
        seed(DB)
    engine = MaskingEngine(SQLiteBackend(DB))
    if args.cmd == "scan" or not engine.tags:
        tags = engine.scan()
        if args.cmd == "scan":
            print(f"{'column':28} {'type':15} {'tag':24} conf  why")
            for t in tags:
                print(f"{t.key:28} {t.data_type:15} {t.tag:24} {t.confidence:<5} {'; '.join(t.reasons)}")
            return
    try:
        for role in ([args.role] if args.cmd == "query" else ROLES):
            res = engine.query(role, args.sql)
            print(f"\n=== role: {role} ({res.row_count} rows) ===")
            table(res.columns, res.rows)

        # Output Quantum Entropy & Post-Quantum Cryptography telemetry
        q_info = engine.quantum.cached_entropy
        pqc_info = engine.pqc.get_public_keys_info()
        print("\n" + "=" * 60)
        print("  QUANTUM ENTROPY (QRNG) & POST-QUANTUM CRYPTOGRAPHY (PQC)")
        print("=" * 60)
        if q_info:
            print(f"[+] Quantum Backend : {q_info.backend_name}")
            print(f"[+] Circuit Spec    : {q_info.num_qubits} qubits (Depth: {q_info.circuit_depth}), {q_info.shots} measurement shots")
            if q_info.bitstring_sample:
                print(f"[+] Measured Bits   : {', '.join(q_info.bitstring_sample[:4])}")
            print(f"[+] Active QRNG Seed: {q_info.entropy_hex[:32]}... (SHA3-256)")
            if getattr(q_info, "job_id", None):
                print(f"[+] Live IBM Job ID : {q_info.job_id} (View at https://cloud.ibm.com/quantum/instances)")
            if q_info.error_message:
                print(f"[i] Backend Note    : {q_info.error_message}")

        if res.audit_record:
            rec = res.audit_record
            print("-" * 60)
            print(f"[+] PQC Signature   : {rec.sig_alg}")
            print(f"[+] ML-DSA Key ID   : {rec.key_id}")
            print(f"[+] Digital Sig     : {rec.signature[:32]}... ({len(rec.signature)} chars)")
            print(f"[+] Hash Chain Link : {rec.entry_hash[:32]}... (SHA3-256)")

        # Demonstrate ML-KEM-768 envelope encryption
        enc_env = engine.pqc.envelope_encrypt(f"query_id={res.audit_record.query_id if res.audit_record else 'demo'}")
        print(f"[+] PQC Envelope Enc: {enc_env['algorithm']}")
        print(f"[+] ML-KEM Ciphertext: {enc_env['kem_ciphertext'][:32]}... (NIST FIPS 203)")
        print("=" * 60)
    except QueryRejected as exc:
        sys.exit(f"Rejected: {exc}")


if __name__ == "__main__":
    main()
