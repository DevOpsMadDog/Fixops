"""End-to-end tests for decision tree with real CVE data."""

from __future__ import annotations

from core.decision_tree import DecisionTreeOrchestrator


class TestDecisionTreeE2E:
    """End-to-end tests with real CVE data."""

    def test_e2e_cve_2017_0144_eternalblue(self):
        """Test decision tree with CVE-2017-0144 (EternalBlue)."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2017-0144",
                    "published": "2017-03-14T00:00:00.000Z",
                    "lastModified": "2020-09-28T12:58:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.1,
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-119"}]}  # Buffer Overflow
                ],
                "references": [
                    {
                        "url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0144",
                        "tags": ["Vendor Advisory", "Patch"],
                    }
                ],
            }
        ]

        exploit_signals = {
            "kev": {"vulnerabilities": [{"cveID": "CVE-2017-0144"}]},
            "epss": {"CVE-2017-0144": 0.97},  # Very high EPSS
        }

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(cve_feed, exploit_signals=exploit_signals)

        assert len(results) == 1
        result = results["CVE-2017-0144"]

        assert result.enrichment is not None
        assert result.enrichment.cve_id == "CVE-2017-0144"
        assert result.enrichment.kev_listed is True
        assert result.enrichment.epss_score == 0.97
        assert result.enrichment.cvss_score == 8.1
        assert "CWE-119" in result.enrichment.cwe_ids
        assert result.enrichment.has_vendor_advisory is True
        assert result.enrichment.age_days > 2500  # Old vulnerability

        assert result.forecast is not None
        assert (
            result.forecast.p_exploit_now > 0.70
        )  # High probability due to KEV + EPSS
        assert result.forecast.p_exploit_30d >= result.forecast.p_exploit_now

        assert result.threat_model is not None
        assert result.threat_model.attack_complexity == "high"  # AC:H in CVSS
        assert result.threat_model.privileges_required == "none"  # PR:N
        assert result.threat_model.user_interaction == "none"  # UI:N

        assert result.compliance is not None
        assert "CWE-119" in result.compliance.cwe_ids
        assert len(result.compliance.control_mappings) > 0

        assert result.verdict in ("exploitable", "needs_review")
        assert result.verdict_confidence > 0.60
        assert len(result.verdict_reasoning) > 0

    def test_e2e_cve_2022_22965_spring4shell(self):
        """Test decision tree with CVE-2022-22965 (Spring4Shell)."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2022-22965",
                    "published": "2022-04-01T00:00:00.000Z",
                    "lastModified": "2023-11-07T03:44:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-94"}]}  # Code Injection
                ],
                "references": [
                    {
                        "url": "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
                        "tags": ["Vendor Advisory", "Patch"],
                    }
                ],
            }
        ]

        exploit_signals = {
            "kev": {"vulnerabilities": [{"cveID": "CVE-2022-22965"}]},
            "epss": {"CVE-2022-22965": 0.89},
        }

        graph = {
            "nodes": [
                {"id": "vuln:CVE-2022-22965", "type": "vulnerability"},
                {
                    "id": "comp:spring-framework",
                    "type": "component",
                    "name": "spring-framework",
                },
            ],
            "edges": [
                {"source": "comp:spring-framework", "target": "vuln:CVE-2022-22965"},
            ],
        }

        cnapp_exposures = [
            {
                "asset": "spring-framework",
                "type": "internet-facing",
            }
        ]

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(
            cve_feed,
            exploit_signals=exploit_signals,
            graph=graph,
            cnapp_exposures=cnapp_exposures,
        )

        result = results["CVE-2022-22965"]

        assert result.enrichment.kev_listed is True
        assert result.enrichment.epss_score == 0.89
        assert result.enrichment.cvss_score == 9.8
        assert result.enrichment.has_vendor_advisory is True

        assert (
            result.forecast.p_exploit_now > 0.80
        )  # Very high due to KEV + high EPSS + high CVSS

        assert result.threat_model.attack_complexity == "low"  # AC:L
        assert result.threat_model.privileges_required == "none"  # PR:N
        assert result.threat_model.exposure_level == "internet"
        assert (
            result.threat_model.attack_path_found is True
        )  # Network + low complexity + internet
        assert len(result.threat_model.critical_assets) > 0

        assert result.verdict == "exploitable"  # Clear exploitable verdict
        assert result.verdict_confidence > 0.70
        assert result.legacy_verdict == "block"

    def test_e2e_cve_2023_4911_looney_tunables(self):
        """Test decision tree with CVE-2023-4911 (Looney Tunables)."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-4911",
                    "published": "2023-10-03T00:00:00.000Z",
                    "lastModified": "2024-01-21T01:46:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 7.8,
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {"value": "CWE-122"}  # Heap-based Buffer Overflow
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt",
                        "tags": ["Third Party Advisory"],
                    }
                ],
            }
        ]

        exploit_signals = {
            "kev": {"vulnerabilities": []},
            "epss": {"CVE-2023-4911": 0.12},
        }

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(cve_feed, exploit_signals=exploit_signals)

        result = results["CVE-2023-4911"]

        assert result.enrichment.kev_listed is False
        assert result.enrichment.epss_score == 0.12
        assert result.enrichment.cvss_score == 7.8
        assert (
            result.enrichment.has_vendor_advisory is False
        )  # Only third party advisory

        assert (
            result.forecast.p_exploit_now < 0.50
        )  # Lower probability - not in KEV, moderate EPSS

        assert result.threat_model.attack_complexity == "low"  # AC:L
        assert (
            result.threat_model.privileges_required == "low"
        )  # PR:L (requires local access)
        assert result.threat_model.user_interaction == "none"  # UI:N
        assert result.threat_model.attack_path_found is False  # Local only (AV:L)

        assert result.verdict in ("needs_review", "not_exploitable")
        assert result.legacy_verdict in ("defer", "allow")

    def test_e2e_multiple_cves_comparison(self):
        """Test decision tree with multiple CVEs to compare verdicts."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-HIGH",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            },
            {
                "cve": {
                    "id": "CVE-2023-LOW",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                                "baseScore": 2.5,
                            }
                        }
                    ]
                },
                "references": [
                    {
                        "url": "https://vendor.com/patch",
                        "tags": ["Vendor Advisory", "Patch"],
                    }
                ],
            },
        ]

        exploit_signals = {
            "kev": {"vulnerabilities": [{"cveID": "CVE-2023-HIGH"}]},
            "epss": {
                "CVE-2023-HIGH": 0.95,
                "CVE-2023-LOW": 0.01,
            },
        }

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(cve_feed, exploit_signals=exploit_signals)

        high_risk = results["CVE-2023-HIGH"]
        assert high_risk.forecast.p_exploit_now > 0.70
        assert high_risk.verdict in ("exploitable", "needs_review")

        low_risk = results["CVE-2023-LOW"]
        assert low_risk.forecast.p_exploit_now < 0.20
        assert low_risk.verdict in ("not_exploitable", "needs_review")

        assert high_risk.forecast.p_exploit_now > low_risk.forecast.p_exploit_now
        assert high_risk.verdict_confidence >= low_risk.verdict_confidence

    def test_e2e_with_llm_results(self):
        """Test decision tree integration with LLM results."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-TEST",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            }
                        }
                    ]
                },
            }
        ]

        llm_results = {
            "CVE-2023-TEST": {
                "explanation": "Critical vulnerability with active exploitation in the wild. "
                "Immediate patching required.",
                "confidence": 0.92,
                "consensus": {
                    "action": "block",
                    "models_agree": True,
                },
            }
        }

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(cve_feed, llm_results=llm_results)

        result = results["CVE-2023-TEST"]
        assert result.llm_explanation == llm_results["CVE-2023-TEST"]["explanation"]
        assert result.llm_confidence == 0.92
        assert result.llm_consensus is not None

        assert result.verdict_confidence > 0.70

    def test_e2e_compliance_framework_integration(self):
        """Test decision tree with compliance framework requirements."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-SQL",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "weaknesses": [{"description": [{"value": "CWE-89"}]}],  # SQL Injection
            }
        ]

        overlay = {
            "decision_tree": {
                "required_frameworks": ["NIST 800-53", "PCI DSS", "ISO 27001"]
            }
        }

        orchestrator = DecisionTreeOrchestrator(overlay=overlay)
        results = orchestrator.analyze(cve_feed)

        result = results["CVE-2023-SQL"]
        assert result.compliance is not None
        assert "CWE-89" in result.compliance.cwe_ids
        assert len(result.compliance.control_mappings) > 0

        assert "NIST 800-53" in result.compliance.frameworks_affected
        assert "PCI DSS" in result.compliance.frameworks_affected

    def test_e2e_verdict_reasoning_quality(self):
        """Test that verdict reasoning is comprehensive and actionable."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-REASON",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            }
        ]

        exploit_signals = {
            "kev": {"vulnerabilities": [{"cveID": "CVE-2023-REASON"}]},
            "epss": {"CVE-2023-REASON": 0.90},
        }

        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze(cve_feed, exploit_signals=exploit_signals)

        result = results["CVE-2023-REASON"]
        reasoning = result.verdict_reasoning

        assert len(reasoning) >= 2  # Should have multiple reasoning points

        reasoning_text = " ".join(reasoning).lower()
        assert any(
            keyword in reasoning_text
            for keyword in [
                "kev",
                "probability",
                "exploit",
                "attack",
                "path",
                "reachability",
            ]
        )

    def test_e2e_empty_cve_feed(self):
        """Test decision tree with empty CVE feed."""
        orchestrator = DecisionTreeOrchestrator()
        results = orchestrator.analyze([])

        assert len(results) == 0

    def test_e2e_custom_thresholds(self):
        """Test decision tree with custom verdict thresholds."""
        cve_feed = [
            {
                "cve": {
                    "id": "CVE-2023-THRESHOLD",
                    "published": "2023-01-01T00:00:00.000Z",
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                "baseScore": 6.5,
                            }
                        }
                    ]
                },
            }
        ]

        overlay_strict = {
            "decision_tree": {
                "thresholds": {
                    "not_exploitable_max": 0.05,  # Very strict
                    "exploitable_min": 0.90,  # Very strict
                }
            }
        }

        overlay_lenient = {
            "decision_tree": {
                "thresholds": {
                    "not_exploitable_max": 0.30,  # Lenient
                    "exploitable_min": 0.50,  # Lenient
                }
            }
        }

        orchestrator_strict = DecisionTreeOrchestrator(overlay=overlay_strict)
        results_strict = orchestrator_strict.analyze(cve_feed)

        orchestrator_lenient = DecisionTreeOrchestrator(overlay=overlay_lenient)
        results_lenient = orchestrator_lenient.analyze(cve_feed)

        result_strict = results_strict["CVE-2023-THRESHOLD"]
        result_lenient = results_lenient["CVE-2023-THRESHOLD"]

        assert result_strict.verdict in (
            "exploitable",
            "not_exploitable",
            "needs_review",
        )
        assert result_lenient.verdict in (
            "exploitable",
            "not_exploitable",
            "needs_review",
        )
