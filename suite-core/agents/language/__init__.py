"""Language-specific agents.

Agents for each supported language that automatically push data.
"""

from agents.language.go_agent import GoAgent
from agents.language.java_agent import JavaAgent
from agents.language.javascript_agent import JavaScriptAgent
from agents.language.python_agent import PythonAgent

__all__ = [
    "PythonAgent",
    "JavaScriptAgent",
    "JavaAgent",
    "GoAgent",
]
