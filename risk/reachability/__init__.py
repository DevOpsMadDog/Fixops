"""Enterprise-grade reachability analysis for vulnerability management."""

from risk.reachability.analyzer import ReachabilityAnalyzer
from risk.reachability.git_integration import GitRepositoryAnalyzer
from risk.reachability.code_analysis import CodeAnalyzer, AnalysisResult
from risk.reachability.call_graph import CallGraphBuilder
from risk.reachability.data_flow import DataFlowAnalyzer
from risk.reachability.cache import AnalysisCache

# Proprietary modules (no OSS dependencies)
from risk.reachability.proprietary_analyzer import (
    ProprietaryReachabilityAnalyzer,
    ProprietaryPatternMatcher,
)
from risk.reachability.proprietary_scoring import ProprietaryScoringEngine
from risk.reachability.proprietary_threat_intel import ProprietaryThreatIntelligenceEngine
from risk.reachability.proprietary_consensus import ProprietaryConsensusEngine

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
