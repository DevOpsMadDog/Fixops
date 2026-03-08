"""Coverage tests for core.quantum_crypto — HybridQuantumSigner."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import json
import pytest
from core.quantum_crypto import HybridQuantumSigner, HybridSignature


class TestHybridQuantumSigner:
    @pytest.fixture
    def signer(self):
        return HybridQuantumSigner(quantum_enabled=False, security_level=3)

    def test_instantiation(self, signer):
        assert signer is not None

    def test_get_key_info(self, signer):
        info = signer.get_key_info()
        assert isinstance(info, dict)

    def test_sign_data(self, signer):
        data = b"test vulnerability finding data"
        signature = signer.sign(data)
        assert isinstance(signature, HybridSignature)

    def test_verify_signature(self, signer):
        data = b"evidence chain data"
        signature = signer.sign(data)
        result = signer.verify(data, signature)
        assert isinstance(result, dict)

    def test_sign_json(self, signer):
        obj = {"finding_id": "CVE-2024-001", "severity": "critical"}
        json_str, signature = signer.sign_json(obj)
        assert isinstance(json_str, str)
        assert isinstance(signature, HybridSignature)
        parsed = json.loads(json_str)
        assert parsed["finding_id"] == "CVE-2024-001"

    def test_sign_empty_data(self, signer):
        signature = signer.sign(b"")
        assert isinstance(signature, HybridSignature)

    def test_sign_large_data(self, signer):
        data = b"x" * 10000
        signature = signer.sign(data)
        assert isinstance(signature, HybridSignature)


class TestHybridSignature:
    def test_fields(self):
        signer = HybridQuantumSigner(quantum_enabled=False)
        sig = signer.sign(b"test")
        # Should have standard signature fields
        assert sig is not None
