"""
MITRE ATT&CK Mapper — CWE→TTP mapping, coverage analysis, heatmap data.

Maps security findings to MITRE ATT&CK v14 techniques and measures coverage
across the full Enterprise matrix. Complements the existing mitre_mapper.py
(which focuses on the full mapping engine) with a higher-level coverage and
gap analysis API.

All data is embedded — no external API calls (air-gap safe).

Key classes:
    MITREATTACKMapper   — main public API
    TechniqueMapping    — a single CWE/keyword→technique mapping result
    ATTACKCoverage      — overall coverage statistics
    TechniqueGap        — an uncovered technique

Usage::

    mapper = MITREATTACKMapper()
    mappings = mapper.map_finding_to_techniques({"cwe_id": "CWE-89", "title": "SQL injection"})
    coverage = mapper.calculate_coverage(findings_list)
    gaps     = mapper.identify_gaps(coverage.covered_technique_ids)
    heatmap  = mapper.generate_heatmap_data(findings_list)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Confidence constants
# ---------------------------------------------------------------------------

HIGH = "HIGH"
MED = "MED"
LOW = "LOW"

# ---------------------------------------------------------------------------
# Top-50 ATT&CK Enterprise techniques (v14) embedded database
# tactic: human-readable primary tactic name
# tactic_id: TA* identifier
# subtechniques: child technique IDs (informational only)
# ---------------------------------------------------------------------------

TECHNIQUES: Dict[str, Dict[str, Any]] = {
    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechniques": [],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechniques": ["T1566.001", "T1566.002", "T1566.003"],
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechniques": [],
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechniques": [],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "subtechniques": ["T1078.001", "T1078.003"],
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "subtechniques": [],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechniques": [],
    },
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": ["T1059.001", "T1059.002", "T1059.003", "T1059.006", "T1059.007"],
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": [],
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": [],
    },
    "T1059.006": {
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": [],
    },
    "T1059.007": {
        "name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": [],
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": [],
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechniques": ["T1204.001", "T1204.002"],
    },
    # Persistence
    "T1505": {
        "name": "Server Software Component",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "subtechniques": ["T1505.003"],
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "subtechniques": [],
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "subtechniques": [],
    },
    # Privilege Escalation
    "T1055": {
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "subtechniques": ["T1055.001", "T1055.012"],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "subtechniques": [],
    },
    # Defense Evasion
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "subtechniques": [],
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "subtechniques": [],
    },
    # Credential Access
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": ["T1552.001", "T1552.002", "T1552.003", "T1552.004"],
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": [],
    },
    "T1552.002": {
        "name": "Unsecured Credentials: Credentials in Registry",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": [],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": ["T1110.001", "T1110.003"],
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": [],
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": [],
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechniques": [],
    },
    # Discovery
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "subtechniques": [],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "subtechniques": [],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "subtechniques": [],
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "subtechniques": [],
    },
    # Lateral Movement
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "subtechniques": [],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "subtechniques": ["T1021.001", "T1021.004"],
    },
    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "subtechniques": [],
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "subtechniques": [],
    },
    "T1119": {
        "name": "Automated Collection",
        "tactic": "Collection",
        "tactic_id": "TA0009",
        "subtechniques": [],
    },
    # Command and Control
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechniques": ["T1071.001"],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechniques": [],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechniques": [],
    },
    # Exfiltration
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "subtechniques": [],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "subtechniques": [],
    },
    # Impact
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "subtechniques": ["T1499.004"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "subtechniques": [],
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "subtechniques": [],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "subtechniques": [],
    },
}

# ---------------------------------------------------------------------------
# CWE → ATT&CK technique mappings
# Each entry: (technique_id, confidence, rationale)
# ---------------------------------------------------------------------------

CWE_TO_TECHNIQUES: Dict[str, List[tuple]] = {
    # CWE-89: SQL Injection → Exploit Public-Facing Application + Command Interp
    "89": [
        ("T1190", HIGH, "SQL injection directly exploits a public-facing application"),
        ("T1059.006", LOW, "SQLi payloads may execute server-side interpreted code"),
    ],
    # CWE-79: Cross-Site Scripting → JavaScript execution in victim browser
    "79": [
        ("T1059.007", HIGH, "XSS causes execution of JavaScript in victim browser context"),
        ("T1539", MED, "Stored/reflected XSS commonly used to steal session cookies"),
    ],
    # CWE-798: Use of Hard-coded Credentials → Unsecured Credentials
    "798": [
        ("T1552", HIGH, "Hard-coded credentials are a textbook case of unsecured credentials"),
        ("T1552.001", HIGH, "Credentials embedded in source files / config files"),
        ("T1078", MED, "Hard-coded creds enable valid account abuse"),
    ],
    # CWE-22: Path Traversal → File and Directory Discovery
    "22": [
        ("T1083", HIGH, "Path traversal allows attackers to discover and read arbitrary files"),
        ("T1005", MED, "Successful traversal leads to local data collection"),
    ],
    # CWE-78: OS Command Injection → Command and Scripting Interpreter
    "78": [
        ("T1059", HIGH, "OS command injection directly invokes a system command interpreter"),
        ("T1059.003", MED, "Windows cmd.exe commonly targeted by OS command injection"),
        ("T1190", MED, "Command injection exploits a public-facing application"),
    ],
    # CWE-611: XXE → Command/Script execution via external entity loading
    "611": [
        ("T1059", MED, "XXE can be used to trigger SSRF or execute server-side scripts"),
        ("T1083", HIGH, "XXE is widely used for server-side file disclosure"),
    ],
    # CWE-502: Insecure Deserialization → Code execution via interpreter
    "502": [
        ("T1059", HIGH, "Insecure deserialization commonly achieves remote code execution"),
        ("T1059.006", MED, "Python/Java deserialization gadget chains execute interpreted code"),
        ("T1203", HIGH, "Deserialization gadget chains exploit client-facing application logic"),
    ],
    # CWE-306: Missing Authentication → Valid Accounts (no credentials required)
    "306": [
        ("T1078", HIGH, "Missing auth allows adversary to access resources as a valid user"),
        ("T1078.001", MED, "Default/anonymous account access is the common exploitation path"),
        ("T1133", MED, "Unauthenticated external remote services expose the environment"),
    ],
    # CWE-434: Unrestricted Upload → Web shell persistence
    "434": [
        ("T1505.003", HIGH, "Unrestricted file upload is the primary web shell upload vector"),
        ("T1190", MED, "Upload vulnerability exploits a public-facing application"),
    ],
    # CWE-862: Missing Authorization → Privilege Escalation / Valid Accounts
    "862": [
        ("T1078", HIGH, "Missing authorization enables low-privileged users to act as higher roles"),
        ("T1068", MED, "Authorization bypass can achieve privilege escalation"),
    ],
    # CWE-918: SSRF → Internal network discovery
    "918": [
        ("T1046", HIGH, "SSRF enables scanning of internal network services"),
        ("T1083", MED, "SSRF can be used to read internal files via file:// URIs"),
        ("T1210", MED, "SSRF pivots to exploit internal/remote services"),
    ],
    # CWE-352: CSRF → User execution of attacker-controlled actions
    "352": [
        ("T1204", HIGH, "CSRF tricks a victim into performing attacker-desired actions"),
        ("T1059.007", MED, "JavaScript-based CSRF attacks execute code in browser context"),
    ],
    # CWE-287: Improper Authentication → Valid Accounts
    "287": [
        ("T1078", HIGH, "Broken authentication allows adversary to masquerade as valid user"),
        ("T1110", MED, "Weak authentication mechanisms facilitate brute-force attacks"),
    ],
    # CWE-200: Information Exposure → Discovery
    "200": [
        ("T1082", MED, "Information disclosure reveals system configuration details"),
        ("T1083", MED, "Path/file disclosure enables further file discovery"),
    ],
    # CWE-601: Open Redirect → Phishing
    "601": [
        ("T1566.002", HIGH, "Open redirect is commonly used in phishing link campaigns"),
    ],
    # CWE-94: Code Injection → Command and Scripting Interpreter
    "94": [
        ("T1059", HIGH, "Code injection achieves arbitrary code execution via interpreter"),
        ("T1190", MED, "Code injection exploits a public-facing application"),
    ],
    # CWE-338: Weak PRNG → Credential/session prediction
    "338": [
        ("T1539", MED, "Weak random number generation may allow session token prediction"),
        ("T1110", LOW, "Predictable tokens can be brute-forced"),
    ],
}

# ---------------------------------------------------------------------------
# Keyword → ATT&CK technique text-match rules
# Each rule: (keyword_set, technique_id, confidence)
# keyword_set: ALL keywords must appear (case-insensitive) in title+description
# ---------------------------------------------------------------------------

KEYWORD_RULES: List[tuple] = [
    # SQL injection keywords
    ({"sql", "injection"}, "T1190", MED),
    ({"sqli"}, "T1190", MED),
    # XSS keywords
    ({"cross-site scripting"}, "T1059.007", MED),
    ({"xss"}, "T1059.007", MED),
    # Command injection
    ({"command injection"}, "T1059", HIGH),
    ({"os command"}, "T1059", HIGH),
    ({"rce"}, "T1059", HIGH),
    ({"remote code execution"}, "T1059", HIGH),
    # Path traversal
    ({"path traversal"}, "T1083", HIGH),
    ({"directory traversal"}, "T1083", HIGH),
    ({"lfi"}, "T1083", MED),
    ({"local file inclusion"}, "T1083", MED),
    # Hard-coded credentials
    ({"hardcoded credential"}, "T1552", HIGH),
    ({"hard-coded credential"}, "T1552", HIGH),
    ({"hard coded password"}, "T1552", HIGH),
    # Deserialization
    ({"deserialization"}, "T1059", HIGH),
    ({"unsafe deserialization"}, "T1059", HIGH),
    # XXE
    ({"xxe"}, "T1083", HIGH),
    ({"xml external entity"}, "T1083", HIGH),
    # SSRF
    ({"ssrf"}, "T1046", HIGH),
    ({"server-side request forgery"}, "T1046", HIGH),
    # Authentication
    ({"missing authentication"}, "T1078", HIGH),
    ({"broken authentication"}, "T1078", HIGH),
    ({"missing auth"}, "T1078", HIGH),
    # File upload
    ({"unrestricted file upload"}, "T1505.003", HIGH),
    ({"malicious file upload"}, "T1505.003", HIGH),
    # CSRF
    ({"csrf"}, "T1204", MED),
    ({"cross-site request forgery"}, "T1204", MED),
    # Open redirect
    ({"open redirect"}, "T1566.002", HIGH),
    # Brute force
    ({"brute force"}, "T1110", HIGH),
    ({"brute-force"}, "T1110", HIGH),
    ({"account lockout"}, "T1110", MED),
    # Information disclosure
    ({"information disclosure"}, "T1082", MED),
    ({"sensitive data exposure"}, "T1082", MED),
]

# Confidence numeric values for scoring
_CONF_SCORE: Dict[str, float] = {HIGH: 1.0, MED: 0.6, LOW: 0.3}

# All tactic IDs (14 tactics, ordered per ATT&CK)
ALL_TACTIC_IDS: List[str] = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
    "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
    "TA0009", "TA0011", "TA0010", "TA0040",
]

ALL_TACTIC_NAMES: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TechniqueMapping:
    """A single finding→technique mapping result."""

    technique_id: str
    technique_name: str
    tactic: str                    # Human-readable tactic name
    confidence: str                # HIGH / MED / LOW
    finding_id: Optional[str]      # Originating finding ID
    match_source: str              # "cwe", "keyword", "manual"
    match_ref: str                 # e.g. "CWE-89", "sql injection"

    @property
    def confidence_score(self) -> float:
        return _CONF_SCORE.get(self.confidence, 0.0)


@dataclass
class ATTACKCoverage:
    """Overall ATT&CK coverage statistics for a set of findings."""

    total_techniques_in_db: int
    covered_technique_ids: Set[str]
    covered_tactic_ids: Set[str]
    technique_coverage_pct: float
    tactic_coverage_pct: float
    # {tactic_name: [technique_ids]}
    tactic_breakdown: Dict[str, List[str]] = field(default_factory=dict)
    # {technique_id: hit_count}
    technique_frequency: Dict[str, int] = field(default_factory=dict)


@dataclass
class TechniqueGap:
    """An ATT&CK technique not covered by any current finding."""

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    priority: str   # HIGH / MED / LOW — based on real-world prevalence


# ---------------------------------------------------------------------------
# Prevalence scoring (higher = more commonly used in the wild)
# Used to prioritise gap analysis output.
# ---------------------------------------------------------------------------

_PREVALENCE: Dict[str, int] = {
    "T1059": 100, "T1078": 95, "T1190": 90, "T1566": 88, "T1552": 85,
    "T1110": 80, "T1083": 75, "T1055": 72, "T1027": 70, "T1505.003": 68,
    "T1046": 65, "T1071": 62, "T1133": 60, "T1210": 58, "T1082": 55,
    "T1213": 52, "T1105": 50, "T1203": 48, "T1068": 45, "T1041": 42,
}


def _prevalence_priority(technique_id: str) -> str:
    score = _PREVALENCE.get(technique_id, 20)
    if score >= 80:
        return HIGH
    if score >= 50:
        return MED
    return LOW


# ---------------------------------------------------------------------------
# MITREATTACKMapper — main public class
# ---------------------------------------------------------------------------


class MITREATTACKMapper:
    """Maps security findings to MITRE ATT&CK techniques and measures coverage.

    Public API:
        map_finding_to_techniques(finding) -> list[TechniqueMapping]
        calculate_coverage(findings)       -> ATTACKCoverage
        identify_gaps(covered_ids)         -> list[TechniqueGap]
        generate_heatmap_data(findings)    -> dict  (ATT&CK Navigator format)
    """

    def __init__(self) -> None:
        self._techniques = TECHNIQUES
        self._cwe_map = CWE_TO_TECHNIQUES
        self._keyword_rules = KEYWORD_RULES

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_cwe(cwe_id: Any) -> Optional[str]:
        """Return bare numeric CWE string, e.g. 'CWE-89' → '89'."""
        if cwe_id is None:
            return None
        s = str(cwe_id).strip().upper().lstrip("CWE-").lstrip("0")
        return s if s.isdigit() else None

    @staticmethod
    def _text_blob(finding: dict) -> str:
        parts = [
            str(finding.get("title", "")),
            str(finding.get("name", "")),
            str(finding.get("description", "")),
        ]
        return " ".join(parts).lower()

    def _match_by_cwe(
        self, cwe_id: Any, finding_id: Optional[str]
    ) -> List[TechniqueMapping]:
        norm = self._normalize_cwe(cwe_id)
        if not norm:
            return []
        rules = self._cwe_map.get(norm, [])
        results: List[TechniqueMapping] = []
        for tid, conf, rationale in rules:
            tech = self._techniques.get(tid)
            if not tech:
                continue
            results.append(
                TechniqueMapping(
                    technique_id=tid,
                    technique_name=tech["name"],
                    tactic=tech["tactic"],
                    confidence=conf,
                    finding_id=finding_id,
                    match_source="cwe",
                    match_ref=f"CWE-{norm}",
                )
            )
        return results

    def _match_by_keywords(
        self, finding: dict, finding_id: Optional[str]
    ) -> List[TechniqueMapping]:
        blob = self._text_blob(finding)
        results: List[TechniqueMapping] = []
        seen: Set[str] = set()
        for keyword_set, tid, conf in self._keyword_rules:
            if tid in seen:
                continue
            if all(kw in blob for kw in keyword_set):
                tech = self._techniques.get(tid)
                if not tech:
                    continue
                seen.add(tid)
                matched_kw = " + ".join(sorted(keyword_set))
                results.append(
                    TechniqueMapping(
                        technique_id=tid,
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        confidence=conf,
                        finding_id=finding_id,
                        match_source="keyword",
                        match_ref=matched_kw,
                    )
                )
        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def map_finding_to_techniques(self, finding: dict) -> List[TechniqueMapping]:
        """Map a single security finding to relevant ATT&CK techniques.

        Matching priority:
        1. CWE ID (highest signal)
        2. Keyword matching against title + description

        Deduplication: if both CWE and keyword match the same technique_id,
        keep the higher-confidence result.

        Args:
            finding: dict with keys: id, title, description, cwe_id, severity

        Returns:
            List of TechniqueMapping, sorted by confidence (HIGH first).
        """
        finding_id = finding.get("id") or finding.get("finding_id")

        cwe_results = self._match_by_cwe(finding.get("cwe_id"), finding_id)
        kw_results = self._match_by_keywords(finding, finding_id)

        # Merge: CWE results take precedence over keyword results for same TID
        merged: Dict[str, TechniqueMapping] = {}
        for m in kw_results:
            merged[m.technique_id] = m
        for m in cwe_results:
            # CWE overrides keyword for same technique
            existing = merged.get(m.technique_id)
            if existing is None or _CONF_SCORE[m.confidence] >= _CONF_SCORE[existing.confidence]:
                merged[m.technique_id] = m

        return sorted(merged.values(), key=lambda m: _CONF_SCORE[m.confidence], reverse=True)

    def calculate_coverage(self, findings: List[dict]) -> ATTACKCoverage:
        """Calculate ATT&CK coverage across a list of findings.

        Args:
            findings: list of finding dicts (same format as map_finding_to_techniques)

        Returns:
            ATTACKCoverage with sets of covered techniques/tactics, percentages,
            per-tactic breakdown, and technique frequency counts.
        """
        covered_tids: Set[str] = set()
        covered_tactic_ids: Set[str] = set()
        technique_frequency: Dict[str, int] = {}
        tactic_breakdown: Dict[str, List[str]] = {}

        for finding in findings:
            mappings = self.map_finding_to_techniques(finding)
            for m in mappings:
                covered_tids.add(m.technique_id)
                technique_frequency[m.technique_id] = technique_frequency.get(m.technique_id, 0) + 1

                tech = self._techniques[m.technique_id]
                tactic_id = tech["tactic_id"]
                tactic_name = tech["tactic"]
                covered_tactic_ids.add(tactic_id)

                if tactic_name not in tactic_breakdown:
                    tactic_breakdown[tactic_name] = []
                if m.technique_id not in tactic_breakdown[tactic_name]:
                    tactic_breakdown[tactic_name].append(m.technique_id)

        total_techs = len(self._techniques)
        total_tactics = len(ALL_TACTIC_IDS)

        return ATTACKCoverage(
            total_techniques_in_db=total_techs,
            covered_technique_ids=covered_tids,
            covered_tactic_ids=covered_tactic_ids,
            technique_coverage_pct=round(len(covered_tids) / total_techs * 100, 2) if total_techs else 0.0,
            tactic_coverage_pct=round(len(covered_tactic_ids) / total_tactics * 100, 2) if total_tactics else 0.0,
            tactic_breakdown=tactic_breakdown,
            technique_frequency=technique_frequency,
        )

    def identify_gaps(self, covered_techniques: Set[str]) -> List[TechniqueGap]:
        """Identify ATT&CK techniques not covered by any current finding.

        Args:
            covered_techniques: set of technique IDs already covered

        Returns:
            List of TechniqueGap, sorted by priority (HIGH first) then technique ID.
        """
        gaps: List[TechniqueGap] = []
        for tid, tech in self._techniques.items():
            if tid not in covered_techniques:
                gaps.append(
                    TechniqueGap(
                        technique_id=tid,
                        technique_name=tech["name"],
                        tactic=tech["tactic"],
                        tactic_id=tech["tactic_id"],
                        priority=_prevalence_priority(tid),
                    )
                )
        # Sort: HIGH first, then MED, then LOW; within same priority sort by TID
        priority_order = {HIGH: 0, MED: 1, LOW: 2}
        gaps.sort(key=lambda g: (priority_order[g.priority], g.technique_id))
        return gaps

    def generate_heatmap_data(self, findings: List[dict]) -> dict:
        """Generate data for ATT&CK Navigator heatmap visualization.

        Returns JSON-compatible dict conforming to ATT&CK Navigator layer
        schema v4.5. Techniques are scored by hit frequency.

        Args:
            findings: list of finding dicts

        Returns:
            dict compatible with MITRE ATT&CK Navigator layer format.
        """
        coverage = self.calculate_coverage(findings)
        freq = coverage.technique_frequency

        # Build technique annotations
        techniques_layer: List[Dict[str, Any]] = []
        for tid, count in freq.items():
            score = min(count * 25, 100)  # cap at 100
            techniques_layer.append(
                {
                    "techniqueID": tid,
                    "score": score,
                    "color": "",
                    "comment": f"Hit {count} time(s) across findings",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False,
                }
            )

        return {
            "name": "ALDECI Finding Coverage",
            "versions": {
                "attack": "14",
                "navigator": "4.9",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "Auto-generated by ALDECI MITREATTACKMapper from security findings",
            "filters": {
                "platforms": [
                    "Linux", "macOS", "Windows", "Network",
                    "PRE", "Containers", "IaaS", "SaaS",
                    "Office 365", "Google Workspace", "Azure AD",
                ],
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [],
            "metadata": [
                {"name": "generated_by", "value": "ALDECI MITREATTACKMapper"},
                {"name": "findings_count", "value": str(len(findings))},
                {"name": "techniques_covered", "value": str(len(coverage.covered_technique_ids))},
                {"name": "tactic_coverage_pct", "value": f"{coverage.tactic_coverage_pct}%"},
            ],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_mapper_instance: Optional[MITREATTACKMapper] = None


def get_mitre_attack_mapper() -> MITREATTACKMapper:
    """Return the shared MITREATTACKMapper singleton."""
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = MITREATTACKMapper()
    return _mapper_instance
