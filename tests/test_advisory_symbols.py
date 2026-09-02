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


def test_patterns_are_scoped_to_the_package_when_one_is_given() -> None:
    """A bare ``%symbol%`` matches a function of that name in ANY package.

    At scale that broke the funnel: symbol-level reported more reachable
    findings than package-level, which is impossible if the symbol query is a
    refinement of the package query. The package argument was being accepted
    and ignored — a parameter that looks like it scopes and does not.
    """
    got = extract_symbols(*CHAIN)
    assert got.reachability_patterns("cryptography") == ["cryptography.%build_chain_inner%"]
    # No package to scope it, so NO pattern — this used to assert
    # ["%build_chain_inner%"], enshrining the unanchored query that produced a
    # false act_now on the pipeline's copy of the same fallback. A bare symbol
    # without a package is unanswerable, and the caller must get nothing back
    # rather than a query that matches on substring.
    assert got.reachability_patterns() == []


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


# --- call evidence, and what is strong enough to rule a finding out ---------


def test_a_call_is_recovered_even_in_rst_double_backticks() -> None:
    """The biggest single source of missed symbols. Of 59 advisories where
    nothing was recovered, 25 named a call — most in RST ``double backticks``,
    which the single-backtick pattern never saw."""
    got = extract_symbols(
        "aiohttp cookie deserialisation",
        "using ``CookieJar.load()`` with untrusted input may allow arbitrary code execution.",
    )
    assert "CookieJar.load" in got.dotted_paths
    assert got.can_rule_out


def test_a_camelcase_receiver_is_kept_when_it_is_being_CALLED() -> None:
    """`RecipientInfo` is a type the flaw operates on; `CookieJar.load()` is an
    entry point a caller reaches. The parentheses are the whole difference, and
    the CamelCase filter alone got the second case wrong."""
    typed = extract_symbols("x", "the `RecipientInfo` structure")
    called = extract_symbols("x", "``CookieJar.load()`` is unsafe")
    assert not typed.known
    assert called.known


def test_a_bare_noun_is_not_strong_enough_to_rule_a_finding_out() -> None:
    """Audited at scale, the bare-backtick path produced `cookies`,
    `session_id` and `allowed_hosts` — a noun, a parameter and a config key.
    Finding no "session_id" in a call graph says nothing about reachability, yet
    it was deleting findings from the queue.

    Such evidence may still be reported (known) but must never eliminate.
    """
    got = extract_symbols("x", "the `session_id` is not verified against the session")
    assert got.known
    assert not got.can_rule_out, (
        "a parameter name is not an entry point; ruling a CVE out on its absence "
        "removes a real finding from the queue on unsound evidence"
    )


def test_patterns_contain_no_duplicates() -> None:
    """A call also lands in dotted_paths, so the same symbol was queried twice."""
    got = extract_symbols("x", "``CookieJar.load()`` and again ``CookieJar.load()``")
    patterns = got.reachability_patterns("aiohttp")
    assert len(patterns) == len(set(patterns)), patterns


# --- JavaScript advisories name files and properties, not just functions ----


def test_a_filename_is_not_an_entry_point() -> None:
    """JS advisories say "the fix is in index.js" constantly. A dotted token
    ending in a source extension is a path, and ruling a finding out because we
    do not call something named `index.js` is nonsense."""
    got = extract_symbols("x", "the fix is in `index.js` and `index.d.ts`")
    assert not got.can_rule_out, got.dotted_paths


def test_an_object_property_is_not_an_entry_point() -> None:
    """"config.proxy is not validated", "req.body is trusted" — data the flaw
    operates on, exactly like `RecipientInfo`. Measured on real npm advisories,
    these came through as callable symbols."""
    got = extract_symbols("x", "`config.proxy` is not validated and `req.body` is trusted")
    assert not got.can_rule_out, got.dotted_paths


def test_a_real_js_call_still_survives_the_filters() -> None:
    """The filters must not swallow the thing they exist to protect."""
    got = extract_symbols("x", "`axios.formToJSON()` recurses without bound")
    assert got.can_rule_out
    assert "axios.formToJSON" in got.dotted_paths


def test_a_symbol_is_not_reported_twice() -> None:
    got = extract_symbols("x", "`axios.formToJSON()` and again `axios.formToJSON()`")
    assert got.dotted_paths == list(dict.fromkeys(got.dotted_paths))
    assert got.calls == list(dict.fromkeys(got.calls))
