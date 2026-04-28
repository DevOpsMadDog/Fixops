"""Tests for the HIBP (Have I Been Pwned) importer.

Test plan:
  1. Parse 5-breach fixture JSON
  2. Year-bucket extraction
  3. Domain filter
  4. Password range API: 5-char hash prefix proxy works
  5. Email check: returns status=needs_credentials when key missing
  6. Idempotent re-import
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure suite-feeds is importable
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for candidate in [
    str(_ROOT / "suite-feeds"),
    str(_ROOT / "suite-core"),
    str(_ROOT / "suite-api"),
]:
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from feeds.hibp.importer import HibpImporter, _ensure_table


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

FIXTURE_BREACHES = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04T00:00:00Z",
        "ModifiedDate": "2022-05-15T23:52:49Z",
        "PwnCount": 152445165,
        "Description": "In October 2013...",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsVerified": True,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2012-05-05",
        "AddedDate": "2016-05-22T00:00:00Z",
        "ModifiedDate": "2016-05-22T00:00:00Z",
        "PwnCount": 164611595,
        "Description": "In May 2016...",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "LogoPath": "",
    },
    {
        "Name": "MySpace",
        "Title": "MySpace",
        "Domain": "myspace.com",
        "BreachDate": "2008-07-01",
        "AddedDate": "2016-05-31T00:00:00Z",
        "ModifiedDate": "2016-05-31T00:00:00Z",
        "PwnCount": 359420698,
        "Description": "In approximately 2008...",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"],
        "IsVerified": True,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "LogoPath": "",
    },
    {
        "Name": "Dropbox",
        "Title": "Dropbox",
        "Domain": "dropbox.com",
        "BreachDate": "2012-07-01",
        "AddedDate": "2016-08-31T00:00:00Z",
        "ModifiedDate": "2016-09-05T00:00:00Z",
        "PwnCount": 68648009,
        "Description": "In mid-2012...",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "LogoPath": "",
    },
    {
        "Name": "Exactis",
        "Title": "Exactis",
        "Domain": "exactis.com",
        "BreachDate": "2018-06-01",
        "AddedDate": "2018-07-11T00:00:00Z",
        "ModifiedDate": "2018-07-11T00:00:00Z",
        "PwnCount": 218870629,
        "Description": "In June 2018...",
        "DataClasses": ["Email addresses", "Phone numbers", "Physical addresses"],
        "IsVerified": False,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
        "LogoPath": "",
    },
]

FIXTURE_RANGE_RESPONSE = (
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n"
    "2AAA1C8B2A74B76D2A3F7B2A1B1B1B1B1B1:1\r\n"
    "3CB543A2B8D07D0B7D3B2A1E1E1E1E1E1E1:7\r\n"
)


# ---------------------------------------------------------------------------
# Helper: build importer against a temp DB with fixture data mocked
# ---------------------------------------------------------------------------

def _make_importer(tmp_db: str, fixture: list | None = None) -> HibpImporter:
    fixture_data = fixture if fixture is not None else FIXTURE_BREACHES
    with patch("feeds.hibp.importer._http_get", return_value=fixture_data):
        imp = HibpImporter(db_path=tmp_db)
    return imp


class TestHibpImporter(unittest.TestCase):

    # ------------------------------------------------------------------
    # Test 1: Parse 5-breach fixture JSON
    # ------------------------------------------------------------------

    def test_parse_5_breach_fixture(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_BREACHES):
                result = imp.import_breaches(idempotent=True)
            self.assertEqual(result["source_count"], 5)
            self.assertEqual(result["breaches_imported"], 5)
            self.assertEqual(result["breaches_skipped"], 0)
            self.assertEqual(imp.total_count(), 5)
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Test 2: Year-bucket extraction
    # ------------------------------------------------------------------

    def test_year_bucket_extraction(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_BREACHES):
                result = imp.import_breaches(idempotent=True)
            by_year = result["by_year"]
            # Adobe=2013, LinkedIn=2012, MySpace=2008, Dropbox=2012, Exactis=2018
            self.assertIn("2013", by_year)
            self.assertIn("2012", by_year)
            self.assertIn("2008", by_year)
            self.assertIn("2018", by_year)
            self.assertEqual(by_year["2012"], 2)  # LinkedIn + Dropbox
            self.assertEqual(result["biggest_breach"], "MySpace")  # 359M
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Test 3: Domain filter
    # ------------------------------------------------------------------

    def test_domain_filter(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_BREACHES):
                imp.import_breaches(idempotent=True)
            result = imp.list_breaches(domain="adobe.com")
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["breaches"][0]["name"], "Adobe")

            result_none = imp.list_breaches(domain="unknown-domain.xyz")
            self.assertEqual(result_none["total"], 0)
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Test 4: Password range API proxy
    # ------------------------------------------------------------------

    def test_password_range_proxy(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_RANGE_RESPONSE):
                result = imp.check_password_range("5BAA6")
            self.assertEqual(result["prefix"], "5BAA6")
            self.assertIsInstance(result["matches"], list)
            self.assertEqual(len(result["matches"]), 3)
            # Verify counts are parsed as integers
            for match in result["matches"]:
                self.assertIn("suffix", match)
                self.assertIsInstance(match["count"], int)
        finally:
            Path(db).unlink(missing_ok=True)

    def test_password_range_prefix_too_short(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with self.assertRaises(ValueError):
                imp.check_password_range("AB")
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Test 5: Email check returns needs_credentials when key missing
    # ------------------------------------------------------------------

    def test_email_check_needs_credentials_when_no_key(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            # Ensure HIBP_API_KEY is absent
            env = {k: v for k, v in os.environ.items() if k != "HIBP_API_KEY"}
            with patch.dict(os.environ, env, clear=True):
                result = imp.check_email("user@example.com")
            self.assertEqual(result["status"], "needs_credentials")
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Test 6: Idempotent re-import
    # ------------------------------------------------------------------

    def test_idempotent_reimport(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_BREACHES):
                first = imp.import_breaches(idempotent=True)
                second = imp.import_breaches(idempotent=True)

            self.assertEqual(first["breaches_imported"], 5)
            self.assertEqual(second["breaches_imported"], 0)
            self.assertEqual(second["breaches_skipped"], 5)
            # Total in DB should still be 5
            self.assertEqual(imp.total_count(), 5)
        finally:
            Path(db).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Bonus: force_update overwrites existing records
    # ------------------------------------------------------------------

    def test_force_update_overwrites(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        try:
            imp = HibpImporter(db_path=db)
            with patch("feeds.hibp.importer._http_get", return_value=FIXTURE_BREACHES):
                first = imp.import_breaches(idempotent=True)
                second = imp.import_breaches(idempotent=False)

            self.assertEqual(first["breaches_imported"], 5)
            self.assertEqual(second["breaches_updated"], 5)
            self.assertEqual(second["breaches_imported"], 0)
        finally:
            Path(db).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
