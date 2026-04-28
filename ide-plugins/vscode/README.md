# ALDECI Security — VS Code Extension

Real-time security scanning powered by the ALDECI CTEM+ platform.

## Features

- **Scan File** — right-click any file in the Explorer and choose "ALDECI: Scan This File" to get inline diagnostics (red squigglies) on vulnerable lines.
- **Scan Workspace** — scan all files in the current workspace against the ALDECI API.
- **Open Dashboard** — launch the ALDECI web dashboard in a webview panel.
- **Status bar** — live scan status shown in the VS Code status bar.

## Requirements

- ALDECI API server running (default: `http://localhost:8000`)
- ALDECI web dashboard running (default: `http://localhost:5173`)
- An ALDECI API key

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aldeci.apiUrl` | `http://localhost:8000` | Base URL of the ALDECI API server |
| `aldeci.apiKey` | `` | API key for authenticating with ALDECI |
| `aldeci.dashboardUrl` | `http://localhost:5173` | URL of the ALDECI web dashboard |

## Sideload Instructions (Development)

1. Build the extension:
   ```bash
   cd ide-plugins/vscode
   npm install
   npm run compile
   ```

2. Package the VSIX:
   ```bash
   npx vsce package
   # produces: aldeci-security-0.0.1.vsix
   ```

3. Install the VSIX in VS Code:
   ```bash
   code --install-extension aldeci-security-0.0.1.vsix
   ```
   Or: open VS Code → Extensions → `...` menu → "Install from VSIX..."

4. Configure your API key in VS Code settings (`aldeci.apiKey`).

5. Right-click any file in the Explorer → "ALDECI: Scan This File".

## Commands

| Command | Description |
|---------|-------------|
| `ALDECI: Scan This File` | Scan the selected/active file |
| `ALDECI: Scan Workspace` | Scan all workspace files |
| `ALDECI: Open Dashboard` | Open the ALDECI dashboard webview |

## API Endpoints Used

- `POST /api/v1/scan/file` — file-level SAST scan
- `POST /api/v1/scan/workspace` — workspace-level scan trigger
