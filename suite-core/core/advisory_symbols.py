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
# Segments after the first may be CamelCase, because the last one is often a
# CLASS: `cryptography.fernet.Fernet`, `django.db.models.Q`. Requiring every
# segment to be lowercase did not merely trim those tails — it failed the whole
# match, because the closing backtick then had nowhere to land, so the path was
# dropped entirely and silently.
#
# Measured: a positive control naming `cryptography.fernet.Fernet`, a symbol
# that IS in the FixOps graph, produced zero patterns and therefore could never
# be reported reachable. The head stays lowercase-only: module roots are
# lowercase, and the head is what the package check compares against.
_DOTTED = re.compile(r"`([a-z_][a-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)`")

# Advisories backtick HOSTNAMES constantly, and a hostname is shaped exactly
# like a module path. This was not hypothetical: run end-to-end against live
# OSV, PYSEC-2026-3554 yielded `foo.example.com` and `bar.example.com` from its
# wildcard-SAN example, and the extractor then "RULED OUT" the CVE by searching
# a call graph for a domain name. Confidently wrong is the one outcome worse
# than undetermined, because undetermined keeps the finding in the queue.
#
# The unit test missed it because it paraphrased that advisory instead of
# quoting it — the test agreed with an idea of the data rather than the data.
# A FILE is not an entry point. JavaScript advisories name files constantly
# ("the fix is in index.js"), and a dotted token ending in a source extension is
# a path, not a symbol. Measured on real npm advisories: the extractor returned
# `index.js` and `index.d.ts` as callable symbols.
_FILE_TAIL = frozenset({
    "js", "ts", "mjs", "cjs", "mts", "cts", "jsx", "tsx",
    "py", "json", "md", "lock", "yaml", "yml", "toml",
})

# "v1.x", "3.14.1" — a version, not a symbol. Advisories are full of them.
_VERSIONISH = re.compile(r"^v?\d+(\.[\dx]+)*$", re.I)

# Object PROPERTIES read like calls in prose — "config.proxy is not validated",
# "req.body is trusted". They are data the flaw operates on, not functions a
# caller reaches, and the same reasoning that rejects `RecipientInfo` rejects
# these. Without this, a JS finding gets ruled out because we do not call
# something named `req.body`.
_PROPERTY_ROOTS = frozenset({
    "req", "res", "request", "response", "config", "options", "opts",
    "ctx", "context", "params", "query", "headers", "server", "client",
    "socket", "stream", "buffer", "process", "window", "document",
})

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


def _is_bare_english_word(symbol: str) -> bool:
    """Is this undotted token a plain word rather than a function name?

    Measured on 21 real Maven advisories for spring-petclinic, the undotted
    tokens surviving into rule-outs were:

        sslmode  required  prefer  allow  disable  extended
        sslfactory  sslhostnameverifier  sslpasswordcallback

    Every one is a JDBC **connection parameter or its value**, lifted out of
    prose like ``sslmode=require``. None is a method. Ruling a finding out
    because the call graph contains no function named ``prefer`` is the
    ``cookies`` mistake for a third time — 5 of 7 Java eliminations rested on
    vocabulary like this, a precision of about 29%.

    A real method name carries a shape that an English word does not: an
    underscore (``pkcs7_decrypt_der``, how Python advisories name functions) or
    an internal capital (``refreshRow``, ``getSource`` — the two Java rule-outs
    that WERE sound). A single all-lowercase run of letters has neither.

    This costs recall on genuinely lowercase one-word functions (``loads``,
    ``dump``). That is the right trade: those are also the tokens most likely to
    collide with ordinary prose, and losing a rule-out only yields
    "undetermined", while a wrong one yields a safety claim.
    """
    token = symbol.strip()
    if not token or "_" in token:
        return False
    if any(character.isupper() for character in token):
        return False
    return token.isalpha()


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

    def rule_out_symbols(self, package: Optional[str] = None) -> List[str]:
        """The symbols specific enough to justify declaring a finding unreachable.

        Auditing the TypeScript run showed why ``known`` is not a high enough
        bar. Advisory prose yielded ``index.d.cts`` (a filename), ``v1.x`` (a
        VERSION STRING), ``JSON.stringify`` (a language builtin) and
        ``proxy.address`` / ``auth.username`` (object properties). Each searched
        the call graph, matched nothing, and produced a confident "unreachable"
        — inflating elimination to 87% on evidence that meant nothing.

        That is the ``cookies`` mistake running the other way: there a real
        finding was closed on a noun, here on a filename.

        A dotted symbol is only trustworthy when its head IS the vulnerable
        package — ``axios.formToJSON`` for axios. Then the advisory is naming
        that package's own API, which is exactly the thing a call graph can
        answer. A bare call with no dot (``pkcs7_decrypt_der``) is kept, because
        that is how Python advisories name functions and it measured well.
        """
        if not package:
            # No package to check the head against. That is a reason to skip the
            # check, not to discard the evidence — a dotted path is still the
            # most specific thing the advisory gave us.
            return list(dict.fromkeys(self.dotted_paths + self.calls + self.symbols))

        head = package.lower().replace("-", "_")
        keep: List[str] = []
        # `symbols` carries bare backticked names — how Python advisories write
        # functions ("`pkcs7_decrypt_der` reported the outcome"). Omitting them
        # here silently disarmed every Python rule-out.
        for symbol in self.dotted_paths + self.calls + self.symbols:
            if "." not in symbol:
                if _is_bare_english_word(symbol):
                    continue
                keep.append(symbol)
                continue
            if symbol.split(".", 1)[0].lower().replace("-", "_") == head:
                keep.append(symbol)
        return list(dict.fromkeys(keep))

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
        trustworthy = set(self.rule_out_symbols(package))
        seen: List[str] = []
        for path in [p for p in self.dotted_paths if p in trustworthy]:
            candidate = f"{path}%"
            if candidate not in seen:
                seen.append(candidate)
        # `or "." not in x` used to sit here, and it re-admitted EVERY undotted
        # symbol after rule_out_symbols had just rejected it — so the filters
        # above protected nothing on this path, which is the path that ships.
        # `trustworthy` already keeps the legitimate bare names (an underscore
        # or an internal capital); the bypass only let the English words back in.
        for symbol in [x for x in self.symbols if x in trustworthy]:
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
        head, _, tail = name.rpartition(".")
        if head.lower() in _HOSTNAME_TAIL or head.lower() in _PROPERTY_ROOTS:
            continue
        if tail in _FILE_TAIL:
            continue
        if name not in calls:
            calls.append(name)

    def _is_symbol_path(name: str) -> bool:
        head, _, tail = name.rpartition(".")
        if tail in _HOSTNAME_TAIL or tail in _FILE_TAIL:
            return False          # a hostname or a filename
        if _VERSIONISH.match(name):
            return False          # "v1.x" is a version, not an entry point
        if head.lower() in _PROPERTY_ROOTS:
            return False          # req.body, config.proxy — data, not an entry point
        return True

    dotted = [m for m in dict.fromkeys(_DOTTED.findall(text)) if _is_symbol_path(m)]

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
    # A dotted call is already in `calls`; adding it to `dotted` too made the
    # same symbol appear twice in every report. reachability_patterns dedupes,
    # but the raw lists are what a human reads.
    dotted = list(dict.fromkeys(dotted + [c for c in calls if "." in c]))

    return AdvisorySymbols(
        symbols=symbols, dotted_paths=dotted, calls=list(dict.fromkeys(calls))
    )
