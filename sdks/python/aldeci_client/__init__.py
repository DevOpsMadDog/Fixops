"""A client library for accessing ALDECI Security Intelligence Platform"""

from .client import AuthenticatedClient, Client

__all__ = (
    "AuthenticatedClient",
    "Client",
)
