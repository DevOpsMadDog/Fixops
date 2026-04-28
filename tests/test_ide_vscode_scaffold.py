"""
Tests for the VS Code IDE extension scaffold.
Verifies manifest fields, command registrations, and sideload instructions.
"""
import json
import re
from pathlib import Path

VSCODE_DIR = Path(__file__).parent.parent / "ide-plugins" / "vscode"


def test_package_json_exists():
    assert (VSCODE_DIR / "package.json").exists(), "package.json must exist"


def test_package_json_manifest_fields():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    assert pkg["name"] == "aldeci-security"
    assert pkg["displayName"] == "ALDECI Security"
    assert pkg["publisher"] == "aldeci"
    assert pkg["version"] == "0.0.1"
    # engines.vscode must be present and target >=1.85
    engines_vscode = pkg["engines"]["vscode"]
    assert "1.85" in engines_vscode, f"Expected vscode ^1.85.0, got {engines_vscode}"


def test_package_json_activation_events():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    events = pkg.get("activationEvents", [])
    assert "onStartupFinished" in events, "activationEvents must include onStartupFinished"


def test_package_json_commands():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    commands = {c["command"] for c in pkg["contributes"]["commands"]}
    assert "aldeci.scanFile" in commands
    assert "aldeci.scanWorkspace" in commands
    assert "aldeci.openDashboard" in commands


def test_package_json_configuration():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    props = pkg["contributes"]["configuration"]["properties"]
    assert "aldeci.apiUrl" in props
    assert "aldeci.apiKey" in props


def test_extension_ts_exists():
    assert (VSCODE_DIR / "src" / "extension.ts").exists()


def test_extension_ts_registers_scan_file():
    src = (VSCODE_DIR / "src" / "extension.ts").read_text()
    assert "aldeci.scanFile" in src, "extension.ts must register aldeci.scanFile command"
    assert "aldeci.scanWorkspace" in src
    assert "aldeci.openDashboard" in src


def test_extension_ts_reads_config():
    src = (VSCODE_DIR / "src" / "extension.ts").read_text()
    assert "getConfiguration('aldeci')" in src or 'getConfiguration("aldeci")' in src


def test_extension_ts_status_bar():
    src = (VSCODE_DIR / "src" / "extension.ts").read_text()
    assert "createStatusBarItem" in src, "extension.ts must create a status bar item"


def test_scan_ts_exists():
    assert (VSCODE_DIR / "src" / "scan.ts").exists()


def test_scan_ts_calls_api():
    src = (VSCODE_DIR / "src" / "scan.ts").read_text()
    assert "/api/v1/scan/file" in src, "scan.ts must call /api/v1/scan/file"
    assert "DiagnosticCollection" in src or "diagnosticCollection" in src or "DiagnosticProvider" in src


def test_dashboard_ts_exists():
    assert (VSCODE_DIR / "src" / "dashboard.ts").exists()


def test_dashboard_ts_opens_issues():
    src = (VSCODE_DIR / "src" / "dashboard.ts").read_text()
    assert "/issues" in src, "dashboard.ts must point to /issues route"
    assert "WebviewPanel" in src or "createWebviewPanel" in src


def test_tsconfig_exists():
    assert (VSCODE_DIR / "tsconfig.json").exists()


def test_tsconfig_outdir():
    cfg = json.loads((VSCODE_DIR / "tsconfig.json").read_text())
    assert cfg["compilerOptions"]["outDir"] == "out"
    assert cfg["compilerOptions"]["module"] == "commonjs"


def test_vscodeignore_exists():
    assert (VSCODE_DIR / ".vscodeignore").exists()


def test_readme_exists():
    assert (VSCODE_DIR / "README.md").exists()


def test_readme_sideload_instructions():
    readme = (VSCODE_DIR / "README.md").read_text()
    assert "code --install-extension" in readme, "README must contain sideload instructions"
    assert "aldeci-security-0.0.1.vsix" in readme


def test_readme_commands_documented():
    readme = (VSCODE_DIR / "README.md").read_text()
    assert "aldeci.scanFile" in readme or "Scan This File" in readme
    assert "aldeci.openDashboard" in readme or "Open Dashboard" in readme


def test_compile_script_defined():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    scripts = pkg.get("scripts", {})
    assert "compile" in scripts, "package.json must have a compile script"
    assert "tsc" in scripts["compile"]


def test_vsce_in_dev_dependencies():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    dev_deps = pkg.get("devDependencies", {})
    assert "@vscode/vsce" in dev_deps, "package.json must have @vscode/vsce in devDependencies"


def test_types_vscode_in_dev_dependencies():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    dev_deps = pkg.get("devDependencies", {})
    assert "@types/vscode" in dev_deps


def test_explorer_context_menu():
    pkg = json.loads((VSCODE_DIR / "package.json").read_text())
    menus = pkg["contributes"].get("menus", {})
    explorer_cmds = [m["command"] for m in menus.get("explorer/context", [])]
    assert "aldeci.scanFile" in explorer_cmds, "scanFile must appear in explorer/context menu"
