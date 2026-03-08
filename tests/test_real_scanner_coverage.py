"""Coverage tests for core.real_scanner — ArchitectureProfile."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.real_scanner import ArchitectureProfile


class TestArchitectureProfile:
    def test_creation_defaults(self):
        profile = ArchitectureProfile()
        assert profile.architecture_class == "unknown"
        assert profile.deployment_model == "unknown"
        assert profile.confidence == 0.0

    def test_to_dict(self):
        profile = ArchitectureProfile(
            architecture_class="cloud-native",
            deployment_model="kubernetes",
            confidence=0.85,
        )
        d = profile.to_dict()
        assert isinstance(d, dict)
        assert d["architecture_class"] == "cloud-native"
        assert d["deployment_model"] == "kubernetes"

    def test_with_tech_stack(self):
        profile = ArchitectureProfile(
            tech_stack={"language": "python", "framework": "fastapi"},
            os_fingerprint={"os": "linux", "distro": "ubuntu"},
            confidence=0.9,
        )
        d = profile.to_dict()
        assert "tech_stack" in d

    def test_with_cloud_provider(self):
        profile = ArchitectureProfile(
            cloud_provider={"name": "AWS", "region": "us-east-1"},
            cdn_waf={"cdn": "cloudfront", "waf": "aws-waf"},
        )
        d = profile.to_dict()
        assert "cloud_provider" in d

    def test_with_security_posture(self):
        profile = ArchitectureProfile(
            security_posture={"tls": True, "hsts": True, "csp": False},
            raw_headers={"Server": "nginx", "X-Powered-By": "Express"},
        )
        d = profile.to_dict()
        assert "security_posture" in d
