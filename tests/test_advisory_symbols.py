"""The symbol extractor is checked against the REAL advisories it was built from.

The text below is taken verbatim from OSV for the three CVEs that pip-audit
found in this repository's own dependencies on 2026-08-29. Paraphrasing it would
make the test agree with an idea of what advisories look like rather than with
what they actually say, and the whole point of this module is that real advisory
prose carries the symbol.

The measurement these guard is in ``docs/REACHABILITY_MEASURED_2026-08-29.md``:
package-level reachability called all three CVEs reachable (94 callers each);
symbol-level ruled two of them out entirely.
"""

from __future__ import annotations

from core.advisory_symbols import extract_symbols

# --- verbatim OSV text ----------------------------------------------------

PKCS7 = (
    "cryptography: PKCS#7 EnvelopedData decryption exposes a Bleichenbacher "
    "oracle through distinguishable errors and timing",
    "### Summary\n\n"
    "`pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime` reported the\n"
    "outcome of decrypting a `RecipientInfo`'s `encryptedKey` in several\n"
    "distinguishable ways, one of which disclosed the exact length recovered from the\n"
    "RSA operation.",
)

CHAIN = (
    "python-cryptography: Duplicate self-signed intermediates can cause "
    "exponential path building",
    "The `build_chain_inner` routine explores candidate chains without "
    "deduplicating equivalent intermediates.",
)

# VERBATIM, and it must stay verbatim. An earlier version of this test
# paraphrased this advisory into prose with no backticks, so it passed while the
# real text made the extractor emit `foo.example.com` as a code symbol and
# "rule out" the CVE by searching a call graph for a domain name. The end-to-end
# run against live OSV caught what the unit test had agreed with.
WILDCARD = (
    "python-cryptography verifier accepts wildcard DNS names allowing escape "
    "from permitted subtrees",
    "### Summary\nIf an intermediate constrained CA permits the DNS name "
    "`foo.example.com`, and the leaf certificate has a wildcard in its DNS SAN "
    "of `*.example.com`, python-cryptography's verifier accepts which allows "
    "escaping outside of the permitted names.",
)


def test_recovers_the_three_pkcs7_functions() -> None:
    got = extract_symbols(*PKCS7)
    assert got.known
    for fn in ("pkcs7_decrypt_der", "pkcs7_decrypt_pem", "pkcs7_decrypt_smime"):
        assert fn in got.symbols, f"{fn} is named in the advisory and must be recovered"


def test_ignores_backticked_data_types() -> None:
    """`RecipientInfo` and `encryptedKey` are what the flaw operates on, not entry
    points a caller reaches. Querying them would look confident and be wrong."""
    got = extract_symbols(*PKCS7)
    assert "RecipientInfo" not in got.symbols
    assert "encryptedKey" not in got.symbols


def test_recovers_a_single_named_routine() -> None:
    got = extract_symbols(*CHAIN)
    assert got.symbols == ["build_chain_inner"]


def test_backticked_hostnames_are_not_mistaken_for_module_paths() -> None:
    """A hostname is shaped exactly like a module path.

    `foo.example.com` matches the dotted-path pattern perfectly. Treating it as
    a symbol makes the extractor confidently rule out a CVE it knows nothing
    about — the one outcome worse than undetermined, because undetermined keeps
    the finding in the queue where a human sees it.
    """
    got = extract_symbols(*WILDCARD)
    assert "foo.example.com" not in got.dotted_paths
    assert not got.dotted_paths, f"hostnames leaked through: {got.dotted_paths}"


def test_an_advisory_naming_no_symbol_reports_unknown_not_empty_success() -> None:
    """The third real CVE. It describes the flaw in prose and names no function.

    This MUST come back not-known, so the finding stays in the queue marked
    undetermined. Reporting it as "no symbols, therefore nothing to reach" would
    claim a safety nobody established.
    """
    got = extract_symbols(*WILDCARD)
    assert not got.known
    assert got.reachability_patterns("cryptography") == [], (
        "an unknown symbol must NOT degrade to a package-level pattern — that "
        "fallback is exactly what produced the 0% noise-reduction measurement"
    )


def test_patterns_are_usable_as_sql_like() -> None:
    got = extract_symbols(*CHAIN)
    patterns = got.reachability_patterns("cryptography")
    assert patterns == ["%build_chain_inner%"]


def test_prose_nouns_in_backticks_are_not_treated_as_symbols() -> None:
    got = extract_symbols(
        "Something is wrong",
        "The `password` field and the `default` `value` are logged in the `response`.",
    )
    assert not got.known, f"prose nouns leaked through as symbols: {got.symbols}"


def test_a_dotted_path_wins_over_its_bare_leaf() -> None:
    """When the advisory gives a full path, query the path — and do not also
    query the leaf, which would search the same thing twice under a looser
    pattern and re-widen what the path just narrowed."""
    got = extract_symbols("x", "The flaw is in `cryptography.x509.ocsp` via `load_der`.")
    assert "cryptography.x509.ocsp" in got.dotted_paths
    assert got.reachability_patterns()[0] == "cryptography.x509.ocsp%"
