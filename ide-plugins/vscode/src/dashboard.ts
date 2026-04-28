import * as vscode from 'vscode';

let panel: vscode.WebviewPanel | undefined;

export function openDashboard(context: vscode.ExtensionContext): void {
  // Reuse existing panel if already open
  if (panel) {
    panel.reveal(vscode.ViewColumn.Two);
    return;
  }

  const cfg = vscode.workspace.getConfiguration('aldeci');
  const dashboardUrl = cfg.get<string>('dashboardUrl', 'http://localhost:5173');

  panel = vscode.window.createWebviewPanel(
    'aldeciDashboard',
    'ALDECI Dashboard',
    vscode.ViewColumn.Two,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
    },
  );

  panel.webview.html = buildWebviewHtml(dashboardUrl, panel.webview);

  panel.onDidDispose(() => {
    panel = undefined;
  }, null, context.subscriptions);
}

function buildWebviewHtml(dashboardUrl: string, _webview: vscode.Webview): string {
  // VS Code webviews cannot directly load external http:// origins in an <iframe>
  // unless the user has a running local server. We render a launch page with a
  // prominent "Open in browser" link and a direct iframe attempt for localhost.
  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ALDECI Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a;
      color: #f8fafc;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .toolbar {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 16px;
      background: #1e293b;
      border-bottom: 1px solid #334155;
      flex-shrink: 0;
    }
    .logo {
      font-weight: 700;
      font-size: 14px;
      color: #6366f1;
      letter-spacing: 0.05em;
    }
    .url-bar {
      flex: 1;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 4px 10px;
      color: #94a3b8;
      font-size: 12px;
      font-family: monospace;
    }
    .open-btn {
      background: #6366f1;
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 5px 14px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
    }
    .open-btn:hover { background: #4f46e5; }
    iframe {
      flex: 1;
      border: none;
      width: 100%;
    }
    .fallback {
      display: none;
      flex: 1;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 16px;
      text-align: center;
      padding: 40px;
    }
    .fallback h2 { font-size: 18px; color: #e2e8f0; }
    .fallback p { font-size: 13px; color: #94a3b8; max-width: 380px; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="toolbar">
    <span class="logo">ALDECI</span>
    <span class="url-bar">${dashboardUrl}/issues</span>
    <a class="open-btn" href="${dashboardUrl}/issues" target="_blank">Open in Browser</a>
  </div>
  <iframe
    id="frame"
    src="${dashboardUrl}/issues"
    sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
    title="ALDECI Dashboard"
  ></iframe>
  <div class="fallback" id="fallback">
    <h2>Cannot reach ALDECI dashboard</h2>
    <p>Make sure the ALDECI dev server is running at <code>${dashboardUrl}</code>, then click "Open in Browser" above or reload this panel.</p>
    <a class="open-btn" href="${dashboardUrl}/issues" target="_blank">Open in Browser</a>
  </div>
  <script>
    const frame = document.getElementById('frame');
    const fallback = document.getElementById('fallback');
    frame.addEventListener('error', () => {
      frame.style.display = 'none';
      fallback.style.display = 'flex';
    });
  </script>
</body>
</html>`;
}
