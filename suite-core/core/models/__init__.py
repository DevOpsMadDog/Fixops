"""Concrete risk model implementations.

Lazy-loaded to avoid pulling heavy ML deps (sklearn/scipy) on every import
of sub-packages like core.models.enterprise.*.
"""


def __getattr__(name: str):
    if name == "BayesianNetworkModel":
        from core.models.bayesian_network import BayesianNetworkModel

        return BayesianNetworkModel
    if name == "BNLRHybridModel":
        from core.models.bn_lr_hybrid import BNLRHybridModel

        return BNLRHybridModel
    if name == "WeightedScoringModel":
        from core.models.weighted_scoring import WeightedScoringModel

        return WeightedScoringModel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["WeightedScoringModel", "BayesianNetworkModel", "BNLRHybridModel"]
