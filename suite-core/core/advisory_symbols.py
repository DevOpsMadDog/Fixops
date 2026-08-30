"""Recover the vulnerable SYMBOL from an advisory, so reachability can be asked
the question it is actually good at.

Measured 2026-08-29 (``docs/REACHABILITY_MEASURED_2026-08-29.md``): the
reachability engine discriminates sharply — 94 callers for ``cryptography.%``,
15 for one module, 0 for a module this codebase never imports. But every SCA
tool we normalise reports *"package version X is vulnerable"* and never *"the
flaw is in function F"*. So the query degrades to ``package.%``, which asks "do
you use this library" — something the dependency file already answered. Every
finding comes back reachable and the noise reduction is zero.

The symbol is not missing. It is in the advisory prose, in backticks:

    `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime`
    reported the outcome of decrypting a `RecipientInfo`'s `encryptedKey` …

Against a real call graph of this repository that single change moved two of
three real CVEs from "reachable" to "not reachable" — because the code never
calls PKCS#7 decryption at all. That is the difference between a queue item an
engineer chases and one they never see.

**What this module refuses to do.** When an advisory names no symbol, it says
so. It does not guess, and it does not let the caller quietly fall back to a
package-level pattern while still labelling the result "reachability". A finding
whose symbol is unknown must stay in the queue, marked unknown — the third CVE
in that measurement is exactly this case. Silently dropping it would be the
product asserting a safety it never established.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = ["AdvisorySymbols", "extract_symbols"]

# Backticked lower_snake_case runs. Deliberately NOT CamelCase: advisories
# backtick their data types constantly (`EnvelopedData`, `RecipientInfo`), and
# those are structures the flaw operates ON, not entry points a caller reaches.
_BACKTICKED = re.compile(r"`([a-z_][a-z0-9_]{3,})`")

# A dotted path is better evidence than a bare name and is taken when present.
_DOTTED = re.compile(r"`([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+)`")

# Advisories backtick HOSTNAMES constantly, and a hostname is shaped exactly
# like a module path. This was not hypothetical: run end-to-end against live
# OSV, PYSEC-2026-3554 yielded `foo.example.com` and `bar.example.com` from its
# wildcard-SAN example, and the extractor then "RULED OUT" the CVE by searching
# a call graph for a domain name. Confidently wrong is the one outcome worse
# than undetermined, because undetermined keeps the finding in the queue.
#
# The unit test missed it because it paraphrased that advisory instead of
# quoting it — the test agreed with an idea of the data rather than the data.
_HOSTNAME_TAIL = frozenset(
    {
        "com", "org", "net", "io", "dev", "co", "uk", "de", "fr", "jp", "cn",
        "edu", "gov", "mil", "info", "biz", "example", "test", "local",
        "localhost", "invalid", "app", "cloud", "sh", "ai", "me", "us", "eu",
    }
)

# Backticks also wrap prose nouns, config keys and CLI flags. These appear in
# advisory text constantly and are never the vulnerable entry point; matching
# one would produce a confident, wrong "not reachable".
# ``CookieJar.load()``, ``load()``, ``aiohttp.helpers.parse()``. The trailing
# "()" is the whole signal — advisories write calls that way regardless of
# whether they use single backticks, RST double backticks, or none at all.
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\(\)")

_NOT_SYMBOLS = frozenset(
    {
        "true", "false", "none", "null", "nil", "self", "this",
        "user", "users", "password", "passwords", "token", "tokens",
        "secret", "secrets", "value", "values", "error", "errors",
        "data", "input", "output", "result", "results", "request",
        "response", "header", "headers", "content", "length", "buffer",
        "string", "bytes", "integer", "boolean", "object", "array",
        "default", "example", "version", "versions", "release",
        "config", "configuration", "option", "options", "setting", "settings",
        "enabled", "disabled", "verify", "validate",
    }
)


@dataclass
class AdvisorySymbols:
    """What an advisory could tell us about where the flaw lives.

    ``known`` is the field callers must branch on. Empty means *undetermined*,
    which is a different state from *not reachable* and must be carried as such
    all the way to the screen.
    """

    symbols: List[str] = field(default_factory=list)
    dotted_paths: List[str] = field(default_factory=list)
    source: str = "advisory-text"
    #: Symbols recovered from an actual CALL — ``CookieJar.load()``. Only these
    #: are strong enough to RULE A FINDING OUT.
    calls: List[str] = field(default_factory=list)

    @property
    def known(self) -> bool:
        return bool(self.symbols or self.dotted_paths)

    @property
    def can_rule_out(self) -> bool:
        """Whether the evidence is strong enough to declare a finding unreachable.

        Auditing the eliminations at scale showed the bare-backtick path
        producing ``cookies``, ``session_id`` and ``allowed_hosts`` — a noun, a
        parameter and a config key. Searching a call graph for "session_id" and
        finding nothing says nothing at all about whether the vulnerability is
        reachable, yet it was deleting findings from the queue.

        A CALL is different: ``CookieJar.load()`` names an entry point, and its
        absence from the graph is real evidence. So rule-outs require call-shaped
        evidence, and everything weaker leaves the finding UNDETERMINED — where a
        human still sees it. This mirrors the measured-vs-estimated distinction
        the verdict engine already makes: act on what was measured, and say so
        when you are guessing.
        """
        return bool(self.calls or self.dotted_paths)

    def reachability_patterns(self, package: Optional[str] = None) -> List[str]:
        """SQL LIKE patterns for ``vulnerable_reachability``.

        Returns an EMPTY list when no symbol is known, rather than falling back
        to ``package.%``. The fallback is what produced the 0% measurement: it
        turns "we don't know where the flaw is" into "you use this library",
        and reports the result as reachability. A caller that gets [] back must
        mark the finding undetermined, not safe.
        """
        if not self.known:
            return []

        # ``package`` was accepted and silently ignored, which made a bare
        # symbol like ``%build_chain_inner%`` match a function of that name in
        # ANY package. At scale that broke the funnel outright: symbol-level
        # could report more reachable findings than package-level, which is
        # impossible if the symbol query is a refinement of the package query.
        # A parameter that looks like it scopes and does not is worse than no
        # parameter, because every caller reads it as scoping.
        seen: List[str] = []
        for path in self.dotted_paths:
            candidate = f"{path}%"
            if candidate not in seen:
                seen.append(candidate)
        for symbol in self.symbols:
            candidate = f"{package}.%{symbol}%" if package else f"%{symbol}%"
            if candidate not in seen:
                seen.append(candidate)
        return seen


def extract_symbols(summary: str = "", details: str = "") -> AdvisorySymbols:
    """Pull the vulnerable symbol names out of advisory prose.

    Deterministic on purpose. An LLM could read these advisories and would
    probably do better on the ones that describe the flaw in words rather than
    naming it — but a regex is auditable, free, offline (which matters for an
    air-gapped deployment) and testable, and it already recovers the symbol for
    two of the three real advisories measured. Escalating the remainder to the
    council is a later, separate decision, not a prerequisite.
    """
    text = f"{summary}\n{details}"

    # A CALL is unambiguous evidence, and it is the single biggest source of
    # missed symbols: of 59 advisories where nothing was recovered, 25 named a
    # call like ``CookieJar.load()`` and 9 a dotted call. They were missed for
    # two reasons — the text uses RST double-backticks rather than single, and
    # the CamelCase filter above rejected the receiver.
    #
    # That filter is right about a TYPE (`RecipientInfo` is what the flaw
    # operates on) and wrong about a METHOD CALL (`CookieJar.load()` is an entry
    # point a caller reaches). The parentheses are what separate them, so match
    # on the parentheses and ignore the backtick style entirely.
    calls = []
    for match in _CALL.finditer(text):
        name = match.group(1)
        leaf = name.rsplit(".", 1)[-1]
        if leaf.lower() in _NOT_SYMBOLS or len(leaf) < 3:
            continue
        if name.rsplit(".", 1)[0].lower() in _HOSTNAME_TAIL:
            continue
        if name not in calls:
            calls.append(name)

    dotted = [
        m
        for m in dict.fromkeys(_DOTTED.findall(text))
        if m.rsplit(".", 1)[-1] not in _HOSTNAME_TAIL
    ]

    seen: List[str] = []
    for name in _BACKTICKED.findall(text):
        if name in _NOT_SYMBOLS or "." in name:
            continue
        if name not in seen:
            seen.append(name)

    # A dotted path already contains its leaf; keep the leaf out of the bare
    # list so the same symbol is not queried twice under two shapes.
    leaves = {p.rsplit(".", 1)[-1] for p in dotted}
    symbols = [s for s in seen if s not in leaves]

    # A call already names its receiver, so it is better evidence than a bare
    # backticked token; keep it out of the plain-symbol list to avoid querying
    # the same thing twice under a looser pattern.
    call_leaves = {c.rsplit(".", 1)[-1] for c in calls}
    symbols = [s for s in symbols if s not in call_leaves] + [
        c for c in calls if "." not in c
    ]
    dotted = dotted + [c for c in calls if "." in c and c not in dotted]

    return AdvisorySymbols(symbols=symbols, dotted_paths=dotted, calls=list(calls))
