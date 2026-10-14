"""Create a deterministic demo financial database with rich synthetic data, disguised columns, and golden records."""
from __future__ import annotations

import os
import random
import sqlite3
import sys

FIRST = [
    "Alice", "Asha", "Ravi", "Meera", "Karthik", "Sneha", "Arjun", "Divya", "Imran", "Priya",
    "Vikram", "Anita", "Rohan", "Nisha", "Suresh", "Lakshmi", "Aman", "Pooja", "Harsha", "Tara"
]
LAST = [
    "Johnson", "Verma", "Reddy", "Nair", "Sharma", "Iyer", "Khan", "Patel", "Rao", "Das", "Mehta"
]
CITIES = ["Springfield", "Pune", "Hyderabad", "Chennai", "Mumbai", "Bengaluru", "New York", "London"]
STREETS = ["742 Evergreen Terrace", "MG Road", "Lake View Rd", "Park Street", "Station Road", "Hill Avenue"]
MERCHANTS = ["Amazon", "Uber", "Netflix", "Swiggy", "Flipkart", "Apple Store", "Starbucks", "Shell"]


def luhn_check_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def make_card(rng: random.Random) -> str:
    body = "4" + "".join(str(rng.randint(0, 9)) for _ in range(14))
    n = body + luhn_check_digit(body)
    return "-".join(n[i:i + 4] for i in range(0, 16, 4))


def compute_iban_check(country_code: str, bban: str) -> str:
    """Computes ISO 7064 mod-97 check digits for IBAN."""
    converted = ""
    for ch in (bban + country_code + "00"):
        if ch.isdigit():
            converted += ch
        else:
            converted += str(ord(ch.upper()) - 55)
    remainder = int(converted) % 97
    check = 98 - remainder
    return f"{check:02d}"


def make_ssn(rng: random.Random) -> str:
    """Generates valid US SSN format avoiding invalid area 666 and 000/900+."""
    area = rng.randint(101, 899)
    while area == 666:
        area = rng.randint(101, 899)
    group = rng.randint(10, 99)
    serial = rng.randint(1000, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"


def make_iban(rng: random.Random, bank_code="37040044", acct="0532013000") -> str:
    bban = f"{bank_code}{acct}"
    chk = compute_iban_check("DE", bban)
    return f"DE{chk}{bban}"


def seed(path: str, n_customers: int = 50, seed_value: int = 42) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    rng = random.Random(seed_value)
    conn = sqlite3.connect(path)

    # Tables with compatibility aliases (id and customer_id, etc.)
    conn.executescript("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER,
            first_name TEXT,
            last_name TEXT,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            ssn TEXT,
            dob TEXT,
            address TEXT,
            city TEXT,
            country TEXT,
            notes TEXT,            -- Disguised column: contains SSN in >80% of rows
            ssn_verified INTEGER,  -- Decoy column: BOOLEAN, must NOT be tagged
            contact TEXT,          -- Alternate email
            created_at TEXT
        );

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            account_id INTEGER,
            customer_id INTEGER,
            iban TEXT,
            account_number TEXT,
            card_number TEXT,
            balance REAL,
            currency TEXT,
            account_type TEXT,
            opened_at TEXT
        );

        CREATE TABLE cards (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER,
            card_number TEXT,
            card_type TEXT,
            expiry TEXT,
            holder_name TEXT
        );

        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            txn_id INTEGER,
            account_id INTEGER,
            amount REAL,
            merchant TEXT,
            ts TEXT,
            txn_date TEXT
        );
    """)

    txn_counter = 1
    for cid in range(1, n_customers + 1):
        if cid == 1:
            # Golden Record Customer 1
            first_name = "Alice"
            last_name = "Johnson"
            full_name = "Alice Johnson"
            email = "alice.johnson@example.com"
            phone = "+1 (415) 555-0134"
            ssn = "123-45-6789"
            dob = "1990-05-17"
            address = "742 Evergreen Terrace"
            city = "Springfield"
            country = "US"
            notes = "321-54-9876"  # Disguised SSN
            ssn_verified = 1
            contact = "alt.alice@example.com"
            created_at = "2024-01-15 10:30:00"

            iban = "DE89370400440532013000"
            account_number = "0532013000"
            balance = 25432.50
            currency = "EUR"
            card_number = "4111-1111-1111-1111"
            card_type = "VISA"
            expiry = "2029-12"
            holder_name = "Alice Johnson"
        else:
            first_name = rng.choice(FIRST)
            last_name = rng.choice(LAST)
            full_name = f"{first_name} {last_name}"
            email = f"{first_name.lower()}.{last_name.lower()}{cid}@example.com"
            phone = f"+1 ({rng.randint(200, 999)}) {rng.randint(100, 999)}-{rng.randint(1000, 9999)}"
            ssn = make_ssn(rng)
            dob = f"{rng.randint(1965, 2003)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
            city = rng.choice(CITIES)
            country = "US" if city in ["Springfield", "New York"] else "IN"
            address = f"{rng.randint(10, 990)} {rng.choice(STREETS)}, {city}"

            # Disguised column trap: 85% rows have SSN format
            if rng.random() < 0.85:
                notes = make_ssn(rng)
            else:
                notes = "Customer requested paperless statement."

            ssn_verified = 1 if rng.random() > 0.3 else 0
            contact = f"alt.{email}"
            created_at = f"2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d} 09:00:00"

            acct_digits = f"{rng.randint(10**9, 10**10 - 1)}"
            account_number = acct_digits
            iban = make_iban(rng, acct=acct_digits[:10])
            balance = round(rng.choice([rng.uniform(500, 8500), rng.uniform(12000, 75000), rng.uniform(120000, 850000)]), 2)
            currency = rng.choice(["USD", "EUR", "GBP"])
            card_number = make_card(rng)
            card_type = rng.choice(["VISA", "MASTERCARD", "AMEX"])
            expiry = f"202{rng.randint(6, 9)}-{rng.randint(1, 12):02d}"
            holder_name = full_name

        conn.execute(
            """INSERT INTO customers (id, customer_id, first_name, last_name, full_name, email, phone, ssn, dob, address, city, country, notes, ssn_verified, contact, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cid, cid, first_name, last_name, full_name, email, phone, ssn, dob, address, city, country, notes, ssn_verified, contact, created_at)
        )

        conn.execute(
            """INSERT INTO accounts (id, account_id, customer_id, iban, account_number, card_number, balance, currency, account_type, opened_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (cid, cid, cid, iban, account_number, card_number, balance, currency, rng.choice(["SAVINGS", "CHECKING", "INVESTMENT"]), created_at)
        )

        conn.execute(
            """INSERT INTO cards (id, customer_id, card_number, card_type, expiry, holder_name)
               VALUES (?,?,?,?,?,?)""",
            (cid, cid, card_number, card_type, expiry, holder_name)
        )

        for _ in range(rng.randint(1, 4)):
            amt = round(rng.uniform(15.0, 3500.0), 2)
            merch = rng.choice(MERCHANTS)
            ts = f"2026-0{rng.randint(1, 9)}-{rng.randint(1, 28):02d} 14:22:00"
            conn.execute(
                """INSERT INTO transactions (id, txn_id, account_id, amount, merchant, ts, txn_date)
                   VALUES (?,?,?,?,?,?,?)""",
                (txn_counter, txn_counter, cid, amt, merch, ts, ts[:10])
            )
            txn_counter += 1

    # Load MOCK_DATA.csv if available
    csv_candidates = [
        "MOCK_DATA.csv",
        os.path.join(os.path.dirname(path) or ".", "MOCK_DATA.csv"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "MOCK_DATA.csv"),
    ]
    mock_csv = next((p for p in csv_candidates if os.path.exists(p)), None)
    if mock_csv:
        import csv
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mock_users (
                id INTEGER PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                gender TEXT,
                ip_address TEXT
            );
        """)
        with open(mock_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            mock_rows = [
                (int(r["id"]), r["first_name"], r["last_name"], r["email"], r["gender"], r["ip_address"])
                for r in reader
            ]
            conn.executemany(
                "INSERT OR REPLACE INTO mock_users (id, first_name, last_name, email, gender, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
                mock_rows
            )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/bank.db"
    seed(target)
    print(f"Successfully seeded rich bank database at {target}")
