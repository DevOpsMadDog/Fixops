"""Tests for Security Blogs RSS Aggregator importer.

Test plan:
1. Parse fixture RSS XML for 1 source
2. Multiple-source aggregation
3. Filter by source
4. Filter by contains_text=ransomware
5. Idempotent re-import (dedup by id)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-feeds is importable
_SUITE_FEEDS = Path(__file__).resolve().parents[1] / "suite-feeds"
if str(_SUITE_FEEDS) not in sys.path:
    sys.path.insert(0, str(_SUITE_FEEDS))

# ---------------------------------------------------------------------------
# Fixture RSS XML strings
# ---------------------------------------------------------------------------

_RSS_KREBS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Krebs on Security</title>
    <link>https://krebsonsecurity.com</link>
    <item>
      <title>Ransomware Gang Claims Attack on Hospital Network</title>
      <link>https://krebsonsecurity.com/2026/04/ransomware-hospital/</link>
      <description>A major ransomware group has claimed responsibility for disrupting hospital systems.</description>
      <guid>https://krebsonsecurity.com/2026/04/ransomware-hospital/</guid>
      <pubDate>Mon, 27 Apr 2026 10:00:00 +0000</pubDate>
      <author>Brian Krebs</author>
      <category>Ransomware</category>
    </item>
    <item>
      <title>New Phishing Kit Targets Banking Customers</title>
      <link>https://krebsonsecurity.com/2026/04/phishing-kit-banking/</link>
      <description>Security researchers have uncovered a sophisticated phishing kit targeting major banks.</description>
      <guid>https://krebsonsecurity.com/2026/04/phishing-kit-banking/</guid>
      <pubDate>Sun, 26 Apr 2026 08:30:00 +0000</pubDate>
      <author>Brian Krebs</author>
      <category>Phishing</category>
    </item>
  </channel>
</rss>"""

_RSS_SCHNEIER = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Schneier on Security</title>
    <link>https://www.schneier.com</link>
    <item>
      <title>The Risks of AI in Security Decision Making</title>
      <link>https://www.schneier.com/blog/archives/2026/04/ai-security-risks.html</link>
      <description>AI systems are increasingly used for critical security decisions, but this introduces new risks.</description>
      <guid>https://www.schneier.com/blog/archives/2026/04/ai-security-risks.html</guid>
      <pubDate>Sat, 25 Apr 2026 12:00:00 +0000</pubDate>
      <author>Bruce Schneier</author>
    </item>
  </channel>
</rss>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_importer(tmp_path: Path, sources_file: Path) -> Any:
    """Create a SecurityBlogsImporter with an isolated temp DB and sources file."""
    from feeds.security_blogs.importer import SecurityBlogsImporter
    db = str(tmp_path / "security_blogs_test.db")
    return SecurityBlogsImporter(db_path=db, sources_file=str(sources_file))


def _write_sources(tmp_path: Path, urls: list) -> Path:
    sf = tmp_path / "sources.txt"
    sf.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return sf


# ---------------------------------------------------------------------------
# Test 1: Parse fixture RSS XML for 1 source
# ---------------------------------------------------------------------------

def test_parse_single_source_fixture(tmp_path, monkeypatch):
    """Importer correctly parses fixture RSS for one source."""
    import feeds.security_blogs.importer as mod

    # Patch _fetch_bytes to return fixture
    def _mock_fetch(url, timeout=30):
        return _RSS_KREBS

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, ["https://krebsonsecurity.com/feed/"])
    imp = _make_importer(tmp_path, sf)
    result = imp.run()

    assert result["posts_imported"] == 2
    assert "krebsonsecurity.com" in result["by_source"]
    assert result["by_source"]["krebsonsecurity.com"] == 2
    assert result["newest"] is not None


# ---------------------------------------------------------------------------
# Test 2: Multiple-source aggregation
# ---------------------------------------------------------------------------

def test_multiple_source_aggregation(tmp_path, monkeypatch):
    """Importer aggregates posts from multiple feeds."""
    import feeds.security_blogs.importer as mod

    fixture_map = {
        "https://krebsonsecurity.com/feed/": _RSS_KREBS,
        "https://www.schneier.com/blog/atom.xml": _RSS_SCHNEIER,
    }

    def _mock_fetch(url, timeout=30):
        return fixture_map.get(url)

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, list(fixture_map.keys()))
    imp = _make_importer(tmp_path, sf)
    result = imp.run()

    assert result["posts_imported"] == 3  # 2 krebs + 1 schneier
    assert "krebsonsecurity.com" in result["by_source"]
    assert "schneier.com" in result["by_source"]
    assert result["by_source"]["krebsonsecurity.com"] == 2
    assert result["by_source"]["schneier.com"] == 1


# ---------------------------------------------------------------------------
# Test 3: Filter by source
# ---------------------------------------------------------------------------

def test_filter_by_source(tmp_path, monkeypatch):
    """list_posts(source=...) returns only posts from that source."""
    import feeds.security_blogs.importer as mod

    fixture_map = {
        "https://krebsonsecurity.com/feed/": _RSS_KREBS,
        "https://www.schneier.com/blog/atom.xml": _RSS_SCHNEIER,
    }

    def _mock_fetch(url, timeout=30):
        return fixture_map.get(url)

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, list(fixture_map.keys()))
    imp = _make_importer(tmp_path, sf)
    imp.run()

    krebs_posts = imp.list_posts(source="krebsonsecurity.com")
    schneier_posts = imp.list_posts(source="schneier.com")

    assert len(krebs_posts) == 2
    assert len(schneier_posts) == 1
    assert all(p["source"] == "krebsonsecurity.com" for p in krebs_posts)
    assert all(p["source"] == "schneier.com" for p in schneier_posts)


# ---------------------------------------------------------------------------
# Test 4: Filter by contains_text=ransomware
# ---------------------------------------------------------------------------

def test_filter_contains_text_ransomware(tmp_path, monkeypatch):
    """list_posts(contains_text='ransomware') returns only matching posts."""
    import feeds.security_blogs.importer as mod

    fixture_map = {
        "https://krebsonsecurity.com/feed/": _RSS_KREBS,
        "https://www.schneier.com/blog/atom.xml": _RSS_SCHNEIER,
    }

    def _mock_fetch(url, timeout=30):
        return fixture_map.get(url)

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, list(fixture_map.keys()))
    imp = _make_importer(tmp_path, sf)
    imp.run()

    ransomware_posts = imp.list_posts(contains_text="ransomware")

    # Only the first Krebs item mentions ransomware in title/summary
    assert len(ransomware_posts) == 1
    assert "ransomware" in ransomware_posts[0]["title"].lower() or \
           "ransomware" in (ransomware_posts[0]["summary"] or "").lower()


# ---------------------------------------------------------------------------
# Test 5: Idempotent re-import (dedup by id)
# ---------------------------------------------------------------------------

def test_idempotent_reimport(tmp_path, monkeypatch):
    """Running the importer twice does not duplicate posts."""
    import feeds.security_blogs.importer as mod

    def _mock_fetch(url, timeout=30):
        return _RSS_KREBS

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, ["https://krebsonsecurity.com/feed/"])
    imp = _make_importer(tmp_path, sf)

    result1 = imp.run()
    result2 = imp.run()  # second run — same data

    # Both runs succeed
    assert result1["posts_imported"] == 2

    # Second run upserts same IDs — ON CONFLICT updates, rowcount behaviour may vary
    # but total count in DB must still be 2
    total = imp.total_count()
    assert total == 2


# ---------------------------------------------------------------------------
# Test 6: Skip failed/404 sources gracefully
# ---------------------------------------------------------------------------

def test_skip_failed_source(tmp_path, monkeypatch):
    """Sources that return None (timeout/404) are skipped without crashing."""
    import feeds.security_blogs.importer as mod

    def _mock_fetch(url, timeout=30):
        if "krebsonsecurity" in url:
            return _RSS_KREBS
        return None  # simulate timeout/404 for others

    monkeypatch.setattr(mod, "_fetch_bytes", _mock_fetch)

    sf = _write_sources(tmp_path, [
        "https://krebsonsecurity.com/feed/",
        "https://www.nonexistent-feed-404.example.com/feed/",
    ])
    imp = _make_importer(tmp_path, sf)
    result = imp.run()

    # Only krebs posts imported; no crash
    assert result["posts_imported"] == 2
    assert result["by_source"].get("nonexistent-feed-404.example.com", 0) == 0
