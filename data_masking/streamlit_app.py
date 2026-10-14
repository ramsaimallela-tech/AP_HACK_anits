"""Streamlit dashboard for Smart Data Masking System."""
import hashlib
import os
import sqlite3
import time
from dataclasses import asdict

import pandas as pd
import streamlit as st

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from masking.maskers import POLICIES
from seed import seed

# Sync Streamlit Cloud secrets to environment if deployed on Streamlit Cloud
try:
    if hasattr(st, "secrets"):
        for k, v in st.secrets.items():
            if k not in os.environ and isinstance(v, str):
                os.environ[k] = v
except Exception:
    pass

DB = os.environ.get("BANK_DB", "data/bank.db")
COLORS = {"partial": "#fff3cd", "hash": "#dbe7ff", "redact": "#f8d7da"}
EXAMPLES = {
    "Customers (Basic Select)": "SELECT customer_id, full_name, email, phone, ssn, dob FROM customers LIMIT 10",
    "Join (cards + balance)": "SELECT c.full_name, a.account_number, a.card_number, a.balance "
                              "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 10",
    "Alias + math (Lineage tracked)": "SELECT ssn AS tax_ref, balance*1.1 AS projected "
                                     "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 10",
    "Bypass Attempt: WHERE ssn LIKE (Blocked)": "SELECT customer_id, full_name FROM customers WHERE ssn LIKE '123%'",
    "Bypass Attempt: ORDER BY ssn (Blocked)": "SELECT customer_id, full_name FROM customers ORDER BY ssn",
    "CTE Query (Lineage preserved)": "WITH cte AS (SELECT c.customer_id, c.ssn, a.balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id) "
                                     "SELECT ssn AS user_ssn, balance * 2 AS double_bal FROM cte LIMIT 5",
    "Aggregate Query": "SELECT city, COUNT(*) AS customers, SUM(balance) AS total "
                       "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id GROUP BY city",
    "External Dataset: mock_users (MOCK_DATA.csv)": "SELECT id, first_name, last_name, email, ip_address FROM mock_users LIMIT 10",
}

st.set_page_config(page_title="Smart Data Masking System", layout="wide", page_icon="🛡️")


def compute_db_hash(path: str) -> str:
    """Computes SHA-256 of SQLite database dump to prove physical immutability."""
    if not os.path.exists(path):
        return "N/A"
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    h = hashlib.sha256()
    for line in conn.iterdump():
        h.update(line.encode("utf-8"))
    conn.close()
    return h.hexdigest()


@st.cache_resource
def get_engine():
    if not os.path.exists(DB):
        seed(DB, n_customers=50)
    eng = MaskingEngine(SQLiteBackend(DB))
    if not eng.tags:
        eng.scan()
    return eng


def show(result):
    df = pd.DataFrame(result.rows, columns=result.columns)
    action = {r["column"]: r["action"] for r in result.column_report}

    def paint(col):
        color = COLORS.get(action.get(col.name))
        return [f"background-color: {color}; color: #111" if color else ""] * len(col)

    if df.columns.is_unique:
        st.dataframe(df.style.apply(paint, axis=0), hide_index=True, use_container_width=True)
    else:
        st.dataframe(df, hide_index=True, use_container_width=True)
    protected = [r for r in result.column_report if r["action"] != "none"]
    if protected:
        st.caption("Protected: " + ", ".join(f'{r["column"]} ({r["tag"]} → {r["action"]})' for r in protected))


engine = get_engine()

# Sidebar: Role & Quantum Controls
st.sidebar.title("Access & Controls")
role = st.sidebar.radio("Active Role", list(POLICIES), index=1)

st.sidebar.markdown("---")
st.sidebar.subheader("Quantum Key Management (QRNG)")

custom_token = st.sidebar.text_input(
    "IBM Quantum API Token",
    value=os.environ.get("IBM_QUANTUM_TOKEN", "T6KyBK14yiRleq4lX-bXRVnGuYjHSC8vpuHcnJ_o1YSt"),
    type="password",
    help="Enter API token from quantum.ibm.com",
)

backend_choice = st.sidebar.selectbox(
    "IBM Quantum Backend",
    options=["ibm_fez", "ibm_marrakesh", "ibm_kingston"],
    index=0,
    help="Select live IBM Quantum superconducting processor (156-qubit Heron architecture)",
)
engine.quantum.set_backend(backend_choice)

col_qbtn1, col_qbtn2 = st.sidebar.columns(2)
with col_qbtn1:
    if st.button("Connect IBM", type="secondary"):
        if custom_token:
            new_res = engine.quantum.set_token(custom_token)
            if new_res.is_ibm_cloud:
                st.sidebar.success(f"Connected: {new_res.backend_name}")
            else:
                st.sidebar.warning("Using Qiskit Aer (Local Physics Sim)")
with col_qbtn2:
    if st.button("Rotate Seed", type="secondary"):
        engine.quantum.generate_entropy()
        st.sidebar.success("Entropy seed rotated!")

if st.sidebar.button(f"🚀 Submit Circuit to {backend_choice}", type="primary"):
    try:
        with st.sidebar.spinner(f"Submitting Hadamard circuit to {backend_choice}..."):
            j_info = engine.quantum.submit_job_to_ibm_cloud(backend_name=backend_choice)
            st.sidebar.success(f"Job Active on {j_info['backend']}!\nID: `{j_info['job_id']}`")
            st.sidebar.markdown(f"**[🔗 View Job on IBM Platform]({j_info['platform_url']})**")
            st.sidebar.markdown(f"**[🔗 IBM Cloud Workloads]({j_info['cloud_url']})**")
            # Show H-gate circuit (original design)
            st.sidebar.markdown("**✅ Original H-Gate Circuit (your design):**")
            st.sidebar.code(j_info['circuit_ascii'], language="text")
            # Explain transpilation
            st.sidebar.info(
                "🔧 **Why IBM shows RZ+SX gates instead of H?**\n\n"
                "IBM quantum hardware cannot run the H gate directly. "
                "The transpiler converts each H gate into its hardware-native equivalent: "
                "**RZ(π/2) → SX → RZ(π/2)**. This is mathematically identical to H. "
                "To see the original H gates on the IBM platform, click the **\'Qiskit\' tab** in the Circuit section."
            )
    except Exception as exc:
        st.sidebar.error(f"Submission note: {exc}")

# Quantum Provenance Panel
q_res = engine.quantum.cached_entropy
if q_res:
    with st.sidebar.expander("Quantum Provenance Details", expanded=True):
        st.write(f"**Backend:** `{q_res.backend_name}`")
        st.write(f"**Mode:** {'🟢 IBM Quantum Platform' if q_res.is_ibm_cloud else '🔵 Qiskit Aer (Local Quantum Sim)'}")
        st.write(f"**Qubits / Depth:** {q_res.num_qubits} qubits (depth: {q_res.circuit_depth})")
        st.write(f"**Measurement Shots:** {q_res.shots}")
        if getattr(q_res, "job_id", None):
            st.write(f"**Live IBM Job ID:** `{q_res.job_id}`")
            st.markdown(f"[🔗 View Job on IBM Quantum Platform](https://quantum.ibm.com/jobs/{q_res.job_id})")
            st.markdown("[🔗 IBM Cloud Workloads Console](https://cloud.ibm.com/quantum/instances)")
        st.write(f"**Active Seed (SHA3-256):** `{q_res.entropy_hex[:16]}...`")
        if q_res.bitstring_sample:
            st.write(f"**Quantum Bit Samples:** `{', '.join(q_res.bitstring_sample[:4])}`")
        if q_res.circuit_str:
            st.markdown("**✅ Hadamard Gate Circuit — Your Design (H on all 8 qubits):**")
            st.code(q_res.circuit_str, language="text")
            if q_res.is_ibm_cloud:
                st.caption(
                    "🔧 On IBM hardware, H gates are transpiled to native RZ+SX gates. "
                    "On the IBM Platform website → Circuit tab → click **'Qiskit'** to see the original H gates."
                )
        if q_res.error_message:
            st.caption(f"ℹ️ {q_res.error_message}")
        st.caption(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(q_res.generated_at))}")

st.sidebar.markdown("---")
st.sidebar.markdown("**Role Policy Matrix**")
st.sidebar.table(pd.DataFrame(POLICIES).T.fillna("none"))

# Main Header
st.title("Smart Data Masking System")
st.caption("Dynamic, query-time masking with Quantum Entropy and NIST FIPS 204 (ML-DSA-65) tamper-evident audit logging. Stored data is physically untouched.")

tab_q, tab_cmp, tab_raw, tab_scan, tab_audit = st.tabs(
    ["Query Engine", "Compare Roles", "Raw Database & Integrity", "PII Scanner Catalog", "Post-Quantum Audit Log"]
)

if "sql" not in st.session_state:
    st.session_state.sql = EXAMPLES["Customers (Basic Select)"]


def load_example():
    st.session_state.sql = EXAMPLES[st.session_state.example]


with tab_q:
    st.selectbox("Preset Example Queries", list(EXAMPLES), key="example", on_change=load_example)
    sql = st.text_area("SQL (Read-only SELECT statement)", key="sql", height=110)
    
    col_run, col_time = st.columns([1, 4])
    with col_run:
        run_btn = st.button("Run as " + role, type="primary")

    if run_btn:
        try:
            t0 = time.time()
            res = engine.query(role, sql)
            elapsed = (time.time() - t0) * 1000
            st.success(f"Query executed successfully in {elapsed:.1f} ms | Rows returned: {res.row_count}")
            show(res)

            # Prominent Quantum & Post-Quantum Cryptography output
            st.markdown("---")
            st.markdown("### ⚛️ Quantum Entropy & Post-Quantum Cryptography (PQC) Telemetry")
            q_col, pqc_col = st.columns(2)
            q_info = engine.quantum.cached_entropy
            enc = engine.pqc.envelope_encrypt(f"query_id={res.audit_record.query_id if res.audit_record else 'demo'}")
            rec = res.audit_record

            with q_col:
                st.markdown("#### 🔬 Quantum Entropy (QRNG)")
                if q_info:
                    st.info(
                        f"**Backend:** `{q_info.backend_name}`\n\n"
                        f"**Quantum Circuit:** {q_info.num_qubits} qubits (Depth: {q_info.circuit_depth}) | {q_info.shots} shots\n\n"
                        f"**Hadamard Bitstring Samples:** `[{', '.join(q_info.bitstring_sample[:4])}]`\n\n"
                        f"**Derived Seed (SHA3-256):** `{q_info.entropy_hex[:24]}...`"
                    )
                    if q_info.error_message:
                        st.caption(f"ℹ️ {q_info.error_message}")

            with pqc_col:
                st.markdown("#### 🛡️ NIST Post-Quantum Cryptography (PQC)")
                if rec:
                    st.success(
                        f"**Signature Alg (FIPS 204):** `{rec.sig_alg}`\n\n"
                        f"**ML-DSA-65 Key ID:** `{rec.key_id}`\n\n"
                        f"**Digital Signature Preview:** `{rec.signature[:24]}...` ({len(rec.signature)} chars)\n\n"
                        f"**Chain Hash (SHA3-256):** `{rec.entry_hash[:24]}...`\n\n"
                        f"**ML-KEM-768 Ciphertext (FIPS 203):** `{enc['kem_ciphertext'][:24]}...`"
                    )

            if q_info and getattr(q_info, "circuit_str", None):
                with st.expander("📐 View Quantum Circuit Diagram (8-Qubit Hadamard Superposition)", expanded=True):
                    st.code(q_info.circuit_str, language="text")
                    if getattr(q_info, "job_id", None):
                        st.markdown(f"**Live IBM Quantum Workload ID:** `{q_info.job_id}` | [View Workload in IBM Cloud Console](https://cloud.ibm.com/quantum/instances)")

            with st.expander("🔍 Inspect Cryptographic Envelope & Dilithium Signature Details", expanded=False):
                st.json({
                    "quantum_entropy_qrng": {
                        "backend": q_info.backend_name if q_info else "N/A",
                        "num_qubits": q_info.num_qubits if q_info else 0,
                        "shots": q_info.shots if q_info else 0,
                        "circuit_depth": q_info.circuit_depth if q_info else 0,
                        "bitstring_samples": q_info.bitstring_sample if q_info else [],
                        "entropy_seed_hex": q_info.entropy_hex if q_info else "",
                    },
                    "post_quantum_envelope_encryption_fips_203": enc,
                    "post_quantum_audit_signature_fips_204": {
                        "algorithm": rec.sig_alg if rec else "N/A",
                        "key_id": rec.key_id if rec else "N/A",
                        "signature_base64": rec.signature if rec else "N/A",
                        "entry_hash": rec.entry_hash if rec else "N/A",
                        "prev_hash": rec.prev_hash if rec else "N/A",
                    }
                })

        except QueryRejected as exc:
            st.error(f"Query Rejected by Policy Engine: {exc}")
        except Exception as exc:
            st.error(f"Execution Error: {exc}")

with tab_cmp:
    st.markdown("Execute the same SQL across all roles concurrently to compare views:")
    if st.button("Compare All Roles Side-by-Side"):
        cols = st.columns(len(POLICIES))
        for col, r in zip(cols, POLICIES):
            with col:
                st.subheader(f"Role: {r.upper()}")
                try:
                    show(engine.query(r, st.session_state.sql))
                except QueryRejected as exc:
                    st.warning(f"Blocked: {exc}")
                except Exception as exc:
                    st.error(str(exc))

with tab_raw:
    st.subheader("Physical Storage Verification")
    db_hash = compute_db_hash(DB)
    st.info(f"**Database Integrity Checksum (SHA-256):** `{db_hash}`")
    st.caption("Proof of immutability: The database is opened strictly in read-only mode (`mode=ro`). The checksum remains 100% constant across all queries and sessions.")
    
    tables = engine.backend.list_tables()
    table = st.selectbox("Inspect Underlying Table", tables)
    cols, rows, _ = engine.backend.execute_readonly(f"SELECT * FROM {engine.backend.quote(table)} LIMIT 20")
    st.dataframe(pd.DataFrame(rows, columns=cols), hide_index=True, use_container_width=True)

with tab_scan:
    st.subheader("Automated PII & Financial Sensitivity Catalog")
    st.caption("Heuristic scoring based on tokenized column names, format validators (Luhn, ISO 7064 mod-97, Verhoeff, regex), and sample distributions.")
    
    col_rescan, _ = st.columns([1, 4])
    with col_rescan:
        if st.button("Re-scan Database"):
            engine.scan()
            st.success("Re-scan completed!")
            
    tags_df = pd.DataFrame([
        {
            "Table": t.table,
            "Column": t.column,
            "Type": t.sql_type,
            "Sensitivity Tag": t.tag,
            "Confidence": f"{t.confidence:.1%}",
            "Detector": t.detector,
            "Reasons": "; ".join(t.reasons),
        }
        for t in engine.tags
    ])
    st.dataframe(tags_df, hide_index=True, use_container_width=True)

with tab_audit:
    st.subheader("Tamper-Evident Post-Quantum Audit Log")
    st.caption("Every query is logged with normalized parameters (preventing PII leakage in predicates), linked via SHA3-256 block hash chaining, and signed with NIST FIPS 204 (ML-DSA-65).")
    
    col_v, _ = st.columns([2, 3])
    with col_v:
        if st.button("Verify Complete Hash Chain & ML-DSA Signatures"):
            v_res = engine.verify_audit_trail()
            if v_res.get("valid"):
                st.success(f"Verification Passed! {v_res.get('status')}")
            else:
                st.error(f"Verification Failed! {v_res.get('status')}")

    entries = engine.recent_audit(50)
    if entries:
        st.dataframe(pd.DataFrame(entries), hide_index=True, use_container_width=True)
    else:
        st.info("No audit logs recorded yet. Execute queries in the 'Query Engine' tab to generate records.")
