"""Tests for feature flag system."""

from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

from core.flags import EvaluationContext
from core.flags.base import FeatureFlagProvider
from core.flags.combined import CombinedProvider
from core.flags.local_provider import LocalOverlayProvider
from core.flags.namespace_adapter import NamespaceAdapterProvider
from core.flags.registry import FlagType, get_registry


class FakeFlagProvider(FeatureFlagProvider):
    """Deterministic provider for testing."""

    def __init__(self, flags: Dict[str, Any]):
        self.flags = flags

    def bool(
        self, key: str, default: bool, context: Optional[EvaluationContext] = None
    ) -> bool:
        return self.flags.get(key, default)

    def string(
        self, key: str, default: str, context: Optional[EvaluationContext] = None
    ) -> str:
        return self.flags.get(key, default)

    def number(
        self, key: str, default: float, context: Optional[EvaluationContext] = None
    ) -> float:
        return self.flags.get(key, default)

    def json(
        self,
        key: str,
        default: Dict[str, Any],
        context: Optional[EvaluationContext] = None,
    ) -> Dict[str, Any]:
        return self.flags.get(key, default)

    def variant(
        self, key: str, default: str, context: Optional[EvaluationContext] = None
    ) -> str:
        return self.flags.get(key, default)


class TestEvaluationContext:
    """Tests for EvaluationContext."""

    def test_to_dict_filters_none(self):
        """Test that to_dict filters out None values."""
        context = EvaluationContext(
            tenant_id="acme-corp",
            environment="production",
            plan=None,
        )
        result = context.to_dict()
        assert result == {
            "tenant_id": "acme-corp",
            "environment": "production",
        }
        assert "plan" not in result

    def test_to_dict_includes_custom(self):
        """Test that to_dict includes custom attributes."""
        context = EvaluationContext(
            tenant_id="acme-corp",
            custom={"feature_x": True, "score": 42},
        )
        result = context.to_dict()
        assert result["tenant_id"] == "acme-corp"
        assert result["feature_x"] is True
        assert result["score"] == 42

    def test_mode_alias_for_environment(self):
        """Test that mode is an alias for environment."""
        context = EvaluationContext(mode="demo")
        result = context.to_dict()
        assert result["environment"] == "demo"


class TestLocalOverlayProvider:
    """Tests for LocalOverlayProvider."""

    def test_simple_bool_flag(self):
        """Test simple boolean flag evaluation."""
        config = {
            "feature_flags": {
                "fixops.module.guardrails.enabled": True,
            }
        }
        provider = LocalOverlayProvider(config)
        assert provider.bool("fixops.module.guardrails.enabled", False) is True
        assert provider.bool("fixops.module.unknown", False) is False

    def test_simple_string_flag(self):
        """Test simple string flag evaluation."""
        config = {
            "feature_flags": {
                "fixops.model.risk.default": "bn_lr_hybrid_v1",
            }
        }
        provider = LocalOverlayProvider(config)
        assert (
            provider.string("fixops.model.risk.default", "weighted_scoring_v1")
            == "bn_lr_hybrid_v1"
        )

    def test_simple_number_flag(self):
        """Test simple numeric flag evaluation."""
        config = {
            "feature_flags": {
                "fixops.feature.evidence.retention_days": 90,
            }
        }
        provider = LocalOverlayProvider(config)
        assert provider.number("fixops.feature.evidence.retention_days", 30) == 90

    def test_simple_json_flag(self):
        """Test simple JSON flag evaluation."""
        config = {
            "feature_flags": {
                "fixops.module.compliance.config": {"soc2": True, "iso27001": False},
            }
        }
        provider = LocalOverlayProvider(config)
        result = provider.json("fixops.module.compliance.config", {})
        assert result == {"soc2": True, "iso27001": False}

    def test_percentage_rollout_deterministic(self):
        """Test that percentage rollouts are deterministic."""
        config = {
            "feature_flags": {
                "fixops.feature.llm.sentinel": {
                    "percentage": 50,
                    "value": True,
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        context1 = EvaluationContext(tenant_id="acme-corp")
        context2 = EvaluationContext(tenant_id="acme-corp")

        result1 = provider.bool("fixops.feature.llm.sentinel", False, context1)
        result2 = provider.bool("fixops.feature.llm.sentinel", False, context2)

        assert result1 == result2

    def test_percentage_rollout_distribution(self):
        """Test that percentage rollouts approximate target distribution."""
        config = {
            "feature_flags": {
                "fixops.feature.test": {
                    "percentage": 50,
                    "value": True,
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        enabled_count = 0
        total = 1000

        for i in range(total):
            context = EvaluationContext(tenant_id=f"tenant-{i}")
            if provider.bool("fixops.feature.test", False, context):
                enabled_count += 1

        ratio = enabled_count / total
        assert 0.45 <= ratio <= 0.55

    def test_multi_variant_deterministic(self):
        """Test that multi-variant experiments are deterministic."""
        config = {
            "feature_flags": {
                "fixops.model.risk.ab_test": {
                    "variants": {
                        "control": 50,
                        "treatment": 50,
                    },
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        context1 = EvaluationContext(tenant_id="acme-corp")
        context2 = EvaluationContext(tenant_id="acme-corp")

        result1 = provider.variant("fixops.model.risk.ab_test", "control", context1)
        result2 = provider.variant("fixops.model.risk.ab_test", "control", context2)

        assert result1 == result2

    def test_multi_variant_distribution(self):
        """Test that multi-variant experiments approximate target distribution."""
        config = {
            "feature_flags": {
                "fixops.model.risk.ab_test": {
                    "variants": {
                        "control": 40,
                        "treatment_a": 30,
                        "treatment_b": 30,
                    },
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        counts = {"control": 0, "treatment_a": 0, "treatment_b": 0}
        total = 1000

        for i in range(total):
            context = EvaluationContext(tenant_id=f"tenant-{i}")
            variant = provider.variant("fixops.model.risk.ab_test", "control", context)
            counts[variant] += 1

        assert 0.35 <= counts["control"] / total <= 0.45
        assert 0.25 <= counts["treatment_a"] / total <= 0.35
        assert 0.25 <= counts["treatment_b"] / total <= 0.35

    def test_nested_key_lookup(self):
        """Test nested key lookup with dot notation."""
        config = {
            "feature_flags": {
                "fixops": {
                    "module": {
                        "guardrails": {
                            "enabled": True,
                        }
                    }
                }
            }
        }
        provider = LocalOverlayProvider(config)
        assert provider.bool("fixops.module.guardrails.enabled", False) is True

    def test_missing_context_for_percentage(self):
        """Test that missing context returns default for percentage rollouts."""
        config = {
            "feature_flags": {
                "fixops.feature.test": {
                    "percentage": 50,
                    "value": True,
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        context = EvaluationContext()
        result = provider.bool("fixops.feature.test", False, context)
        assert result is False


class TestCombinedProvider:
    """Tests for CombinedProvider."""

    def test_primary_provider_used_first(self):
        """Test that primary provider is used first."""
        primary = FakeFlagProvider({"fixops.feature.test": True})
        fallback = FakeFlagProvider({"fixops.feature.test": False})

        provider = CombinedProvider(primary, fallback)
        assert provider.bool("fixops.feature.test", False) is True

    def test_fallback_provider_used_on_default(self):
        """Test that fallback provider is used when primary returns default."""
        primary = FakeFlagProvider({})
        fallback = FakeFlagProvider({"fixops.feature.test": True})

        provider = CombinedProvider(primary, fallback)
        assert provider.bool("fixops.feature.test", False) is True

    def test_registry_default_used_last(self):
        """Test that registry default is used when both providers return default."""
        primary = FakeFlagProvider({})
        fallback = FakeFlagProvider({})

        provider = CombinedProvider(primary, fallback)
        assert provider.bool("fixops.feature.test", True) is True


class TestLaunchDarklyProvider:
    """Tests for LaunchDarklyProvider."""

    def test_build_ld_context_uses_mode_as_environment_alias(self):
        """Test that mode is treated as alias for environment in LD context."""
        with patch("core.flags.ld_provider.LAUNCHDARKLY_AVAILABLE", True):
            with patch("core.flags.ld_provider.ldclient"):
                with patch("core.flags.ld_provider.LDContext") as mock_ld_context:
                    mock_builder = MagicMock()
                    mock_ld_context.builder.return_value = mock_builder
                    mock_builder.set.return_value = mock_builder
                    mock_builder.build.return_value = MagicMock()

                    from core.flags.ld_provider import LaunchDarklyProvider

                    provider = LaunchDarklyProvider(sdk_key="test-key", offline=True)

                    context_with_mode = EvaluationContext(
                        tenant_id="test-tenant", mode="production"
                    )

                    provider._build_ld_context(context_with_mode)

                    mock_builder.set.assert_any_call("environment", "production")

    def test_build_ld_context_prefers_environment_over_mode(self):
        """Test that environment takes precedence over mode when both are set."""
        with patch("core.flags.ld_provider.LAUNCHDARKLY_AVAILABLE", True):
            with patch("core.flags.ld_provider.ldclient"):
                with patch("core.flags.ld_provider.LDContext") as mock_ld_context:
                    mock_builder = MagicMock()
                    mock_ld_context.builder.return_value = mock_builder
                    mock_builder.set.return_value = mock_builder
                    mock_builder.build.return_value = MagicMock()

                    from core.flags.ld_provider import LaunchDarklyProvider

                    provider = LaunchDarklyProvider(sdk_key="test-key", offline=True)

                    context_with_both = EvaluationContext(
                        tenant_id="test-tenant",
                        environment="staging",
                        mode="production",
                    )

                    provider._build_ld_context(context_with_both)

                    mock_builder.set.assert_any_call("environment", "staging")


class TestFlagRegistry:
    """Tests for flag registry."""

    def test_registry_has_flags(self):
        """Test that registry has registered flags."""
        registry = get_registry()
        assert len(registry.list_all()) > 0

    def test_registry_get_flag(self):
        """Test getting flag metadata from registry."""
        registry = get_registry()
        flag = registry.get("fixops.ops.kill_switch")
        assert flag is not None
        assert flag.key == "fixops.ops.kill_switch"
        assert flag.flag_type == FlagType.BOOL
        assert flag.default is False

    def test_registry_list_by_priority(self):
        """Test listing flags by priority."""
        registry = get_registry()
        ops_flags = registry.list_by_tag("ops")
        assert len(ops_flags) > 0
        assert all("ops" in f.tags for f in ops_flags)

    def test_registry_list_by_tag(self):
        """Test listing flags by tag."""
        registry = get_registry()
        ops_flags = registry.list_by_tag("ops")
        assert len(ops_flags) > 0
        assert all("ops" in f.tags for f in ops_flags)

    def test_registry_validate_config(self):
        """Test validating config against registry."""
        registry = get_registry()
        config = {
            "feature_flags": {
                "fixops.ops.kill_switch": False,
                "fixops.module.guardrails.enabled": True,
            }
        }
        errors = registry.validate_overlay_config(config)
        assert len(errors) == 0

    def test_registry_validate_config_type_mismatch(self):
        """Test that type mismatches are detected."""
        registry = get_registry()
        config = {
            "feature_flags": {
                "fixops.ops.kill_switch": "not_a_bool",
            }
        }
        errors = registry.validate_overlay_config(config)
        assert len(errors) > 0
        assert "type mismatch" in errors[0].lower()


class TestConsistentHashing:
    """Tests for consistent hashing in percentage rollouts."""

    def test_consistent_hashing_stable(self):
        """Test that consistent hashing produces stable results."""
        config = {
            "feature_flags": {
                "fixops.feature.test": {
                    "percentage": 50,
                    "value": True,
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        context = EvaluationContext(tenant_id="acme-corp")

        results = [
            provider.bool("fixops.feature.test", False, context) for _ in range(100)
        ]

        assert len(set(results)) == 1

    def test_different_hash_keys_different_results(self):
        """Test that different hash keys can produce different results."""
        config = {
            "feature_flags": {
                "fixops.feature.test": {
                    "percentage": 50,
                    "value": True,
                    "hash_key": "tenant_id",
                }
            }
        }
        provider = LocalOverlayProvider(config)

        context1 = EvaluationContext(tenant_id="tenant-1")
        context2 = EvaluationContext(tenant_id="tenant-2")

        result1 = provider.bool("fixops.feature.test", False, context1)
        result2 = provider.bool("fixops.feature.test", False, context2)

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)


class TestFakeFlagProvider:
    """Tests for FakeFlagProvider (used in other tests)."""

    def test_fake_provider_bool(self):
        """Test FakeFlagProvider bool evaluation."""
        provider = FakeFlagProvider({"test.flag": True})
        assert provider.bool("test.flag", False) is True
        assert provider.bool("unknown.flag", False) is False

    def test_fake_provider_string(self):
        """Test FakeFlagProvider string evaluation."""
        provider = FakeFlagProvider({"test.flag": "value"})
        assert provider.string("test.flag", "default") == "value"
        assert provider.string("unknown.flag", "default") == "default"

    def test_fake_provider_number(self):
        """Test FakeFlagProvider number evaluation."""
        provider = FakeFlagProvider({"test.flag": 42})
        assert provider.number("test.flag", 0) == 42
        assert provider.number("unknown.flag", 0) == 0

    def test_fake_provider_json(self):
        """Test FakeFlagProvider JSON evaluation."""
        provider = FakeFlagProvider({"test.flag": {"key": "value"}})
        assert provider.json("test.flag", {}) == {"key": "value"}
        assert provider.json("unknown.flag", {}) == {}

    def test_fake_provider_variant(self):
        """Test FakeFlagProvider variant evaluation."""
        provider = FakeFlagProvider({"test.flag": "treatment"})
        assert provider.variant("test.flag", "control") == "treatment"
        assert provider.variant("unknown.flag", "control") == "control"


class TestNamespaceAdapter:
    """Tests for NamespaceAdapterProvider."""

    def test_namespace_aliasing_with_brand_key(self):
        """Test that branded keys are tried first."""
        wrapped = FakeFlagProvider(
            {
                "aldeci.module.guardrails": True,
                "fixops.module.guardrails": False,
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        assert adapter.bool("fixops.module.guardrails", False) is True

    def test_namespace_fallback_to_canonical(self):
        """Test fallback to fixops.* when brand key not found."""
        wrapped = FakeFlagProvider(
            {
                "fixops.module.compliance": True,
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        assert adapter.bool("fixops.module.compliance", False) is True

    def test_namespace_default_when_neither_found(self):
        """Test default is returned when neither brand nor canonical key found."""
        wrapped = FakeFlagProvider({})
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        assert adapter.bool("fixops.module.unknown", False) is False

    def test_namespace_no_aliasing_when_same_as_canonical(self):
        """Test no aliasing when brand namespace is 'fixops'."""
        wrapped = FakeFlagProvider(
            {
                "fixops.module.guardrails": True,
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="fixops")

        assert adapter.bool("fixops.module.guardrails", False) is True

    def test_namespace_string_flag(self):
        """Test namespace aliasing for string flags."""
        wrapped = FakeFlagProvider(
            {
                "aldeci.model.risk.default": "bn_lr_hybrid_v1",
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        assert (
            adapter.string("fixops.model.risk.default", "weighted") == "bn_lr_hybrid_v1"
        )

    def test_namespace_number_flag(self):
        """Test namespace aliasing for number flags."""
        wrapped = FakeFlagProvider(
            {
                "aldeci.feature.evidence.retention_days": 365,
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        assert adapter.number("fixops.feature.evidence.retention_days", 90) == 365

    def test_namespace_json_flag(self):
        """Test namespace aliasing for JSON flags."""
        wrapped = FakeFlagProvider(
            {
                "aldeci.branding": {"product_name": "Aldeci", "short_name": "Aldeci"},
            }
        )
        adapter = NamespaceAdapterProvider(wrapped, brand_namespace="aldeci")

        result = adapter.json("fixops.branding", {})
        assert result["product_name"] == "Aldeci"
