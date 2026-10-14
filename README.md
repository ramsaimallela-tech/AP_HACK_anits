# Smart Data Masking System for PII & Financial Protection
> **Dynamic Query-Time PII Masking with AST Lineage, Quantum Entropy (QRNG), and NIST FIPS 204 Post-Quantum Signed Auditing**

---

## 📌 Executive Summary & System Overview

This system provides **zero-trust, dynamic, query-time data masking** for databases containing sensitive Personally Identifiable Information (PII) and confidential financial records.

### Key Guarantees:
1. **Underlying Data is Never Modified:** All database connections are opened strictly in read-only mode (`mode=ro`) with SQLite Authorizers blocking all write, alter, attach, and pragma operations. Physical immutability is proven via deterministic SHA-256 database dump checksums before and after queries.
2. **Dynamic In-Memory Masking:** The same database and SQL query return different views based on the caller's role (`admin`, `support`, `analyst`). Unauthenticated or unknown roles fail closed to full redaction.
3. **AST SQL Lineage & Bypass Protection:** Powered by `sqlglot`, the engine traces column lineage across aliases (`ssn AS tax_id`), mathematical transformations (`balance * 1.1`), and Common Table Expressions (`WITH ... AS (...)`). Any attempts by non-admin roles to filter, order, or group by sensitive columns (e.g. `WHERE ssn LIKE '123%'`) are automatically blocked.
4. **Quantum Entropy (QRNG):** Analytical hashing keys are seeded using true quantum superposition state collapse via **Qiskit** ($|\psi\rangle = H^{\otimes n}|0\rangle$), supporting both local physical simulation (`AerSimulator`) and live **IBM Quantum Cloud** execution.
5. **Post-Quantum Cryptographic Audit Chain:** Every executed query has its literals normalized to placeholders (`?`) to prevent PII leakage, is chained via SHA3-256 blocks, and is digitally signed using **NIST FIPS 204 (ML-DSA-65 / CRYSTALS-Dilithium)**.

---

## 🚀 Quickstart & Execution Guide

### 1. Installation
Install core dependencies (including Streamlit, pandas, sqlglot, qiskit, and dilithium-py):
```bash
pip install -r requirements.txt
# Or manually:
pip install streamlit pandas sqlglot qiskit qiskit-aer python-dotenv dilithium-py kyber-py
```

### 2. Configure Environment & IBM Quantum API Key
Create or verify your `.env` file in the project root:
```env
IBM_QUANTUM_TOKEN=YOUR_IBM_QUANTUM_API_TOKEN_HERE
BANK_DB=data/bank.db
```

### 3. Seed Database & Ingest Datasets
```bash
python seed.py
```
* Generates `data/bank.db` with realistic synthetic customers, accounts, cards, and transactions.
* Seeds golden test records, disguised columns (`notes` holding SSNs), and decoy booleans (`ssn_verified`).
* Automatically ingests `MOCK_DATA.csv` (1,000 records) into the `mock_users` table.

### 4. Run Automated Test Suite
```bash
python -m unittest -v
```
* **17/17 unit tests passing:** Validates lineage tracking, predicate blocking, disguised columns, immutability hash, deterministic hashing, role policies, and PostgreSQL backend adapter (read-only enforcement, schema introspection, query pipeline).

### 5. Run CLI Commands
```bash
# Automated PII & financial scan report:
python cli.py scan

# Side-by-side comparison across Admin, Support, and Analyst roles:
python cli.py compare "SELECT full_name, ssn, card_number, balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 3"
```

### 6. Launch Interactive Dashboard
```bash
streamlit run streamlit_app.py
```
Open your browser at `http://localhost:8501`.

---

## 🗄️ Multi-Backend Database Support

The system uses a pluggable `Backend` abstraction (`masking/backends.py`), allowing any database to be used with zero changes to the masking engine. **Two backends are fully implemented and tested:**

### Backend 1: SQLite (Default, Zero-Config)
```python
from masking import SQLiteBackend, MaskingEngine

engine = MaskingEngine(SQLiteBackend("data/bank.db"))
```
* Opened in read-only mode (`mode=ro`) with SQLite Authorizers blocking all write, alter, attach, and pragma operations.
* Used by default in `seed.py`, `cli.py`, `streamlit_app.py`, and all tests.

### Backend 2: PostgreSQL (Production-Ready)
```python
from masking import PostgresBackend, MaskingEngine

# Connect using a PostgreSQL DSN (use a read-only database role in production)
engine = MaskingEngine(PostgresBackend(dsn="postgresql://readonly_user:pass@localhost:5432/bankdb"))
engine.scan()  # Auto-detect PII across all PostgreSQL tables
result = engine.query("support", "SELECT full_name, ssn, balance FROM customers LIMIT 10")
```
* Requires `pip install psycopg2-binary` (optional dependency, not needed for SQLite-only usage).
* Enforces read-only at the driver level via `conn.set_session(readonly=True)`.
* Queries `information_schema.tables` and `information_schema.columns` for schema introspection.
* All masking, lineage tracking, predicate blocking, and audit signing work identically across both backends.

### Backend 3: MySQL (Optional)
```python
from masking import MySQLBackend, MaskingEngine

engine = MaskingEngine(MySQLBackend(host="localhost", user="readonly", password="pass", database="bankdb"))
```
* Requires `pip install pymysql` (optional dependency).
* Sets `SESSION TRANSACTION READ ONLY` to enforce read-only access.

### Adding a New Backend
Implement the 5-method `Backend` interface (`quote`, `list_tables`, `list_columns`, `execute_readonly`, `sample`) and the entire masking stack works automatically.

---

## 🔍 Module-by-Module Walkthrough

### 1. Automated PII Scanner (`masking/scanner.py`)
Scans any database backend or pandas DataFrame and computes confidence scores ($0.0$ to $1.0$) using multi-heuristic scoring:

* **Name Tokenization & Hints:** Splits camelCase and snake_case column names into tokens, checking for strong hints (`ssn`, `card_number`, `iban`, `email`) and weak hints (`contact`, `val`).
* **Algorithmic Format Validators:**
  * **Credit Card:** Luhn algorithm check (`luhn_ok`).
  * **IBAN:** ISO 7064 mod-97 check (`iban_mod97_ok`).
  * **Aadhaar:** ISO/IEC 7064 Verhoeff multiplication & permutation check (`verhoeff_check`).
  * **Email, Phone, IP Address, DOB:** Regex pattern matching and age plausibility validation.
* **Disguised Column Detection:** If a column has an unassuming name like `notes` or `contact` but >80% of its sample values match SSN or email format, content validation overrides the name and tags it appropriately.
* **Decoy Protection:** Boolean columns and verification flags (e.g. `ssn_verified`, `is_active`) are flagged as non-sensitive to prevent false positive masking.

### 2. Role-Based Access Control Policies (`masking/maskers.py`)

| Sensitivity Tag | Admin | Support | Analyst |
|---|---|---|---|
| **`PII_HIGH`**<br>(SSN, Card Number, Aadhaar, Passport) | Cleartext | Partial Mask<br>`4111-XXXX-XXXX-1111`<br>`XXX-XX-6789` | Keyed HMAC-SHA3-256<br>`h_28acc77d2680...` |
| **`PII_MEDIUM`**<br>(Full Name, Email, Phone, DOB, IP) | Cleartext | Partial Mask<br>`a***@example.com`<br>`192.168.X.X` | `[REDACTED]` |
| **`FINANCIAL_CONFIDENTIAL`**<br>(Balance, Account No., IBAN) | Cleartext | Range Buckets<br>`10,000-50,000`<br>`XXXXXX3000` | `[REDACTED]` |
| **`NON_SENSITIVE`**<br>(IDs, Timestamps, System Flags) | Cleartext | Cleartext | Cleartext |

* **Deterministic Hashing for Analysts:** Analysts receive HMAC-SHA3-256 tokens keyed with the quantum entropy seed. Identical customer identities across queries or tables produce identical hash tokens (`h_...`), allowing analysts to perform analytical `JOIN` operations without ever revealing raw PII.
* **Fail-Closed Security:** Any unauthenticated role or untagged column defaults to `[REDACTED]`.

### 3. Dynamic Masking Engine (`masking/engine.py`)
* **`sqlglot` Lineage:** Traces each returned column back to its physical origin. If an alias `tax_ref` is selected from `ssn`, or `balance * 1.1` is calculated, the engine identifies that the underlying source is `PII_HIGH` or `FINANCIAL_CONFIDENTIAL` and enforces the strictest policy.
* **Predicate Security:** Blocks non-admin users from using `PII_HIGH` columns in `WHERE`, `ORDER BY`, `GROUP BY`, or `HAVING` clauses, preventing side-channel inference attacks.
* **Content Fallback:** If a column name is masked or dynamically generated (e.g. `SELECT lower(email) AS e`), rows are sampled against content detectors to catch any residual sensitive data.

### 4. Quantum Random Number Generation (`qrng/`, `masking/quantum_entropy.py`)
* Constructs an $n$-qubit quantum circuit applying Hadamard gates ($H$) across all qubits ($|\psi\rangle = H^{\otimes n}|0\rangle$).
* Measures quantum collapse into bitstrings ({0, 1} with 50% probability).
* Seeds HMAC hashing using 256-bit SHA3-256 digests mixed with quantum measurements and OS urandom.
* Runs on **Qiskit AerSimulator** locally or executes on live **IBM Quantum Cloud** hardware when `IBM_QUANTUM_TOKEN` is configured.

### 5. Post-Quantum Tamper-Evident Audit Chain (`masking/audit.py`, `masking/pqc.py`)
* **Parameter Normalization:** Replaces all numbers and quoted literals with `?` in the logged SQL query, ensuring queries like `WHERE full_name = 'Alice'` never leak names into log files.
* **SHA3-256 Block Chaining:** Each log entry stores the cryptographic hash of the preceding entry (`prev_hash`), forming an immutable ledger.
* **NIST FIPS 204 Signatures:** Each block hash is signed using post-quantum **ML-DSA-65 (Dilithium)** digital signatures.
* **Chain Verifier:** `verify_audit_trail()` iterates through all records, validates sequence IDs, recalculates block hashes, and cryptographically verifies ML-DSA signatures.

---

## 📊 Datasets Included in the System

### 1. `data/bank.db` (Primary Relational Database)
Contains tables modeled after real core-banking schemas:
* `customers`: `id`, `full_name`, `email`, `phone`, `ssn`, `dob`, `address`, `notes` (disguised SSNs), `ssn_verified` (decoy flag), `contact`.
* `accounts`: `account_id`, `customer_id`, `iban`, `account_number`, `card_number`, `balance`, `currency`.
* `cards`: `card_id`, `card_number`, `holder_name`, `expiry`.
* `transactions`: `txn_id`, `account_id`, `amount`, `merchant`, `ts`.

### 2. `MOCK_DATA.csv` (1,000 Mock Identity Records)
* Automatically loaded into the `mock_users` table in `bank.db`.
* Columns: `id`, `first_name`, `last_name`, `email`, `gender`, `ip_address`.
* Demonstrates how the scanner classifies previously unseen schemas and tags `ip_address` as `PII_MEDIUM`.

### 3. `creditcard.csv` (Kaggle Fraud Detection Dataset)
* 284,807 transaction rows with PCA-anonymized features (`V1`–`V28`), `Amount`, and fraud `Class`.
* Useful for demonstrating high-volume financial masking on monetary transaction amounts.

---

## 🖥️ Streamlit Dashboard Walkthrough

When you run `streamlit run streamlit_app.py`, the dashboard provides 5 comprehensive tabs plus a sidebar control panel:

1. **Query Engine:**
   * Run custom or preset SQL queries.
   * Toggle between **Admin**, **Support**, and **Analyst** roles in the sidebar to see dynamic masking in action.
   * Colored cell highlights indicate partial masks (yellow), hashes (blue), or redactions (red).
2. **Compare Roles:**
   * Runs the active SQL query simultaneously across Admin, Support, and Analyst views, displaying results side-by-side.
3. **Raw Database & Integrity:**
   * Displays the physical SHA-256 database dump checksum.
   * Inspect underlying tables directly to prove that raw stored data remains completely unchanged.
4. **PII Scanner Catalog:**
   * Shows all scanned database columns, detected types, confidence percentages, assigned sensitivity tags, and reasoning explanations.
   * Includes a "Re-scan Database" button.
5. **Post-Quantum Audit Log:**
   * Displays the append-only audit log with normalized SQL queries.
   * Click **"Verify Complete Hash Chain & ML-DSA Signatures"** to cryptographically verify the integrity of every entry.
6. **Sidebar Quantum Panel:**
   * Click **"Rotate Key with IBM Quantum / Aer"** to re-generate quantum entropy.
   * Expand **Quantum Provenance Details** to view backend name, qubit count, circuit depth, and sample quantum bitstreams.
