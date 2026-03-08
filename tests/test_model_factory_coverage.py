"""Tests for model_factory — registry creation from overlay config."""

from core.model_factory import create_model_registry_from_config


class TestCreateModelRegistryFromConfig:
    def test_empty_config_returns_none(self):
        result = create_model_registry_from_config({})
        assert result is None

    def test_no_probabilistic_key(self):
        result = create_model_registry_from_config({"other": "value"})
        assert result is None

    def test_probabilistic_not_dict(self):
        result = create_model_registry_from_config({"probabilistic": "invalid"})
        assert result is None

    def test_no_risk_models_key(self):
        result = create_model_registry_from_config({"probabilistic": {}})
        assert result is None

    def test_risk_models_not_dict(self):
        result = create_model_registry_from_config(
            {"probabilistic": {"risk_models": "invalid"}}
        )
        assert result is None

    def test_risk_models_disabled(self):
        result = create_model_registry_from_config(
            {"probabilistic": {"risk_models": {"enabled": False}}}
        )
        assert result is None

    def test_risk_models_enabled_no_models(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {},
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_risk_models_enabled_with_weighted(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {
                            "enabled": True,
                            "priority": 10,
                            "config": {},
                        }
                    },
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_risk_models_all_model_types(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {
                            "enabled": True,
                            "priority": 10,
                            "config": {},
                        },
                        "bayesian_network_v1": {
                            "enabled": True,
                            "priority": 50,
                            "config": {},
                        },
                        "bn_lr_hybrid_v1": {
                            "enabled": True,
                            "priority": 100,
                            "config": {},
                        },
                    },
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_models_not_dict(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": "invalid",
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is None

    def test_default_model_setting(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {"enabled": True, "config": {}},
                    },
                    "default_model": "weighted_scoring_v1",
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_fallback_chain(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {"enabled": True, "config": {}},
                        "bayesian_network_v1": {"enabled": True, "config": {}},
                    },
                    "fallback_chain": ["weighted_scoring_v1", "bayesian_network_v1"],
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_ab_test_config(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {"enabled": True, "config": {}},
                        "bayesian_network_v1": {"enabled": True, "config": {}},
                    },
                    "ab_test": {
                        "enabled": True,
                        "control_model": "weighted_scoring_v1",
                        "treatment_model": "bayesian_network_v1",
                        "traffic_split": 0.5,
                    },
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None

    def test_disabled_models_skipped(self):
        config = {
            "probabilistic": {
                "risk_models": {
                    "enabled": True,
                    "models": {
                        "weighted_scoring_v1": {"enabled": False, "config": {}},
                    },
                }
            }
        }
        result = create_model_registry_from_config(config)
        assert result is not None
