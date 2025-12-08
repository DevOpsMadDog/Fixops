"""Language-specific agents.

Agents for each supported language that automatically push data.
"""

from agents.language.python_agent import PythonAgent
from agents.language.javascript_agent import JavaScriptAgent
from agents.language.java_agent import JavaAgent
from agents.language.go_agent import GoAgent
from agents.language.rust_agent import RustAgent
from agents.language.cpp_agent import CppAgent
from agents.language.ruby_agent import RubyAgent
from agents.language.php_agent import PhpAgent
from agents.language.dotnet_agent import DotNetAgent
from agents.language.swift_agent import SwiftAgent
from agents.language.kotlin_agent import KotlinAgent

__all__ = [
    "PythonAgent",
    "JavaScriptAgent",
    "JavaAgent",
    "GoAgent",
    "RustAgent",
    "CppAgent",
    "RubyAgent",
    "PhpAgent",
    "DotNetAgent",
    "SwiftAgent",
    "KotlinAgent",
]
