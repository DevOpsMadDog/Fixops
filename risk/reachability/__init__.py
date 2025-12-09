"""Enterprise-grade reachability analysis for vulnerability management."""

from risk.reachability.analyzer import ReachabilityAnalyzer
from risk.reachability.cache import AnalysisCache
from risk.reachability.call_graph import CallGraphBuilder
from risk.reachability.code_analysis import AnalysisResult, CodeAnalyzer
from risk.reachability.data_flow import DataFlowAnalyzer
from risk.reachability.git_integration import GitRepositoryAnalyzer

# Proprietary modules (no OSS dependencies)
from risk.reachability.proprietary_analyzer import (
    ProprietaryPatternMatcher,
    ProprietaryReachabilityAnalyzer,
)
from risk.reachability.proprietary_consensus import ProprietaryConsensusEngine
from risk.reachability.proprietary_scoring import ProprietaryScoringEngine
from risk.reachability.proprietary_threat_intel import (
    ProprietaryThreatIntelligenceEngine,
)

__all__ = [
    "ReachabilityAnalyzer",
    "GitRepositoryAnalyzer",
    "CodeAnalyzer",
    "AnalysisResult",
    "CallGraphBuilder",
    "DataFlowAnalyzer",
    "AnalysisCache",
    # Proprietary exports
    "ProprietaryReachabilityAnalyzer",
    "ProprietaryPatternMatcher",
    "ProprietaryScoringEngine",
    "ProprietaryThreatIntelligenceEngine",
    "ProprietaryConsensusEngine",
]
