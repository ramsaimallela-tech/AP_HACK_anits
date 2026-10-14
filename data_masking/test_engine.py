import hashlib
import os
import sqlite3
import tempfile
import unittest
import unittest.mock

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from masking.maskers import partial_mask
from masking.scanner import luhn_ok
from seed import seed


def dump_hash(path):
    conn = sqlite3.connect(path)
    h = hashlib.sha256()
    for line in conn.iterdump():
        h.update(line.encode())
    conn.close()
    return h.hexdigest()


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "bank.db")
        seed(cls.db, n_customers=40)
        cls.engine = MaskingEngine(
            SQLiteBackend(cls.db),
            catalog_path=os.path.join(cls.tmp, "cat.json"),
            audit_path=os.path.join(cls.tmp, "audit.log"),
            secret="test-secret",
        )
        cls.engine.scan()

    def one(self, role, sql):
        r = self.engine.query(role, sql)
        return dict(zip(r.columns, r.rows[0]))

    def test_scanner_tags(self):
        tags = {t.key: t.tag for t in self.engine.tags if t.tag != "NON_SENSITIVE"}
        self.assertEqual(tags["customers.ssn"], "PII_HIGH")
        self.assertEqual(tags["accounts.card_number"], "PII_HIGH")
        self.assertEqual(tags["accounts.balance"], "FINANCIAL_CONFIDENTIAL")
        self.assertEqual(tags["customers.contact"], "PII_MEDIUM")  # found by content, not name
        self.assertEqual(tags["customers.notes"], "PII_HIGH")  # disguised column holding SSN
        self.assertNotIn("customers.ssn_verified", tags)  # decoy boolean flag must not be tagged
        self.assertNotIn("transactions.merchant", tags)

    def test_roles(self):
        sql = "SELECT ssn, card_number, balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id WHERE c.customer_id=1"
        admin, support, analyst = (self.one(r, sql) for r in ("admin", "support", "analyst"))
        self.assertEqual(admin["ssn"], "123-45-6789")
        self.assertEqual(support["card_number"], "4111-XXXX-XXXX-1111")
        self.assertEqual(support["ssn"], "XXX-XX-6789")
        self.assertTrue(analyst["ssn"].startswith("h_"))
        self.assertEqual(analyst["balance"], "[REDACTED]")

    def test_hash_is_deterministic(self):
        sql = "SELECT ssn FROM customers WHERE customer_id=1"
        self.assertEqual(self.one("analyst", sql), self.one("analyst", sql))

    def test_alias_and_expression_cannot_bypass(self):
        row = self.one("analyst", "SELECT ssn AS x, balance*2 AS y FROM customers c JOIN accounts a ON a.customer_id=c.customer_id WHERE c.customer_id=1")
        self.assertTrue(row["x"].startswith("h_"))
        self.assertEqual(row["y"], "[REDACTED]")

    def test_select_star_and_unknown_role(self):
        self.assertEqual(self.one("analyst", "SELECT * FROM customers WHERE customer_id=1")["email"], "[REDACTED]")
        self.assertEqual(self.one("intern", "SELECT full_name FROM customers WHERE customer_id=1")["full_name"], "[REDACTED]")

    def test_predicate_filtering_blocked(self):
        for bad_sql in [
            "SELECT customer_id FROM customers WHERE ssn LIKE '123%'",
            "SELECT customer_id FROM customers WHERE ssn = '123-45-6789'",
            "SELECT customer_id FROM customers ORDER BY ssn",
            "SELECT COUNT(*) FROM customers GROUP BY ssn",
        ]:
            with self.assertRaises(QueryRejected):
                self.engine.query("analyst", bad_sql)
            with self.assertRaises(QueryRejected):
                self.engine.query("support", bad_sql)

        # Admin is permitted
        admin_res = self.engine.query("admin", "SELECT customer_id FROM customers WHERE ssn LIKE '123%'")
        self.assertTrue(len(admin_res.rows) >= 1)

    def test_cte_lineage(self):
        sql = "WITH cte AS (SELECT c.customer_id, c.ssn, a.balance FROM customers c JOIN accounts a ON a.customer_id=c.customer_id) SELECT ssn AS x, balance * 2 AS y FROM cte WHERE customer_id=1"
        row = self.one("analyst", sql)
        self.assertTrue(row["x"].startswith("h_"))
        self.assertEqual(row["y"], "[REDACTED]")

    def test_non_pii_and_count_untouched(self):
        self.assertEqual(self.one("analyst", "SELECT COUNT(*) AS n FROM customers")["n"], 40)
        self.assertNotEqual(self.one("analyst", "SELECT merchant FROM transactions LIMIT 1")["merchant"], "[REDACTED]")

    def test_content_fallback(self):
        row = self.one("analyst", "SELECT lower(email) AS e FROM customers LIMIT 1")
        self.assertEqual(row["e"], "[REDACTED]")

    def test_write_and_multi_statement_rejected(self):
        for bad in ["DELETE FROM customers", "SELECT 1; DROP TABLE customers", "PRAGMA table_info(customers)",
                    "ATTACH DATABASE 'x.db' AS x"]:
            with self.assertRaises((QueryRejected, sqlite3.Error)):
                self.engine.query("admin", bad)

    def test_raw_data_unchanged(self):
        before = dump_hash(self.db)
        for role in ("admin", "support", "analyst"):
            self.engine.query(role, "SELECT * FROM customers")
        self.assertEqual(before, dump_hash(self.db))

    def test_helpers(self):
        self.assertTrue(luhn_ok("4111-1111-1111-1111"))
        self.assertFalse(luhn_ok("4111-1111-1111-1112"))
        self.assertEqual(partial_mask("asha@x.com", "email"), "a***@x.com")


class PostgresBackendTests(unittest.TestCase):
    """Validates the PostgreSQL backend adapter without requiring a live Postgres server.

    Uses unittest.mock to simulate psycopg2 connections, proving the adapter's
    read-only enforcement, schema introspection, and query pipeline work correctly.
    """

    def _make_backend(self):
        from masking.backends import PostgresBackend
        return PostgresBackend(dsn="postgresql://test:test@localhost:5432/testdb")

    @unittest.mock.patch.dict("sys.modules", {"psycopg2": unittest.mock.MagicMock()})
    def test_postgres_quote(self):
        backend = self._make_backend()
        self.assertEqual(backend.quote("ssn"), '"ssn"')
        self.assertEqual(backend.quote('col"name'), '"col""name"')

    @unittest.mock.patch.dict("sys.modules", {"psycopg2": unittest.mock.MagicMock()})
    def test_postgres_readonly_session(self):
        """Ensures the Postgres backend sets readonly=True on connection."""
        import sys
        mock_psycopg2 = sys.modules["psycopg2"]
        mock_conn = unittest.mock.MagicMock()
        mock_psycopg2.connect.return_value = mock_conn

        backend = self._make_backend()
        backend._conn()

        mock_conn.set_session.assert_called_once_with(readonly=True, autocommit=False)

    @unittest.mock.patch.dict("sys.modules", {"psycopg2": unittest.mock.MagicMock()})
    def test_postgres_list_tables(self):
        import sys
        mock_psycopg2 = sys.modules["psycopg2"]
        mock_conn = unittest.mock.MagicMock()
        mock_cursor = unittest.mock.MagicMock()
        mock_cursor.fetchall.return_value = [("customers",), ("accounts",)]
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = unittest.mock.MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        backend = self._make_backend()
        tables = backend.list_tables()
        self.assertEqual(tables, ["customers", "accounts"])

    @unittest.mock.patch.dict("sys.modules", {"psycopg2": unittest.mock.MagicMock()})
    def test_postgres_execute_readonly(self):
        import sys
        mock_psycopg2 = sys.modules["psycopg2"]
        mock_conn = unittest.mock.MagicMock()
        mock_cursor = unittest.mock.MagicMock()
        mock_cursor.description = [("full_name",), ("ssn",)]
        mock_cursor.fetchmany.return_value = [("Alice Johnson", "123-45-6789")]
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = unittest.mock.MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        backend = self._make_backend()
        cols, rows, truncated = backend.execute_readonly("SELECT full_name, ssn FROM customers LIMIT 1")
        self.assertEqual(cols, ["full_name", "ssn"])
        self.assertEqual(rows, [["Alice Johnson", "123-45-6789"]])
        self.assertFalse(truncated)

    def test_postgres_backend_interface_matches_sqlite(self):
        """Proves PostgresBackend implements the same Backend interface as SQLiteBackend."""
        from masking.backends import Backend, PostgresBackend, SQLiteBackend
        for method in ("quote", "list_tables", "list_columns", "execute_readonly", "sample"):
            self.assertTrue(hasattr(PostgresBackend, method), f"PostgresBackend missing {method}")
            self.assertTrue(hasattr(SQLiteBackend, method), f"SQLiteBackend missing {method}")


if __name__ == "__main__":
    unittest.main()
