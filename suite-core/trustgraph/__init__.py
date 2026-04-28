"""
TrustGraph Package for ALDECI.

Provides knowledge storage, MCP server integration, and FastAPI routes for
TrustGraph Knowledge Cores. Lazy imports for performance.
"""

from __future__ import annotations

# Lazy imports for performance
_KNOWLEDGE_STORE = None
_MCP_SERVER = None


def get_knowledge_store():
    """Lazy load and return KnowledgeStore singleton."""
    global _KNOWLEDGE_STORE
    if _KNOWLEDGE_STORE is None:
        from .knowledge_store import KnowledgeStore
        _KNOWLEDGE_STORE = KnowledgeStore()
    return _KNOWLEDGE_STORE


def get_mcp_server():
    """Lazy load and return TrustGraphMCPServer singleton."""
    global _MCP_SERVER
    if _MCP_SERVER is None:
        from .mcp_server import TrustGraphMCPServer
        _MCP_SERVER = TrustGraphMCPServer()
    return _MCP_SERVER


__all__ = [
    "get_knowledge_store",
    "get_mcp_server",
]
