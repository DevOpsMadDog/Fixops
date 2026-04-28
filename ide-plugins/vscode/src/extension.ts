import * as vscode from 'vscode';
import { scanFile, scanWorkspace, AldeciDiagnosticProvider } from './scan';
import { openDashboard } from './dashboard';

let statusBarItem: vscode.StatusBarItem;
let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext): void {
  console.log('ALDECI Security extension activated');

  // Diagnostic collection for inline squigglies
  diagnosticCollection = vscode.languages.createDiagnosticCollection('aldeci');
  context.subscriptions.push(diagnosticCollection);

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = '$(shield) ALDECI';
  statusBarItem.tooltip = 'ALDECI Security — click to scan workspace';
  statusBarItem.command = 'aldeci.scanWorkspace';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  const diagnosticProvider = new AldeciDiagnosticProvider(diagnosticCollection, statusBarItem);

  // Command: scan active/selected file
  const scanFileCmd = vscode.commands.registerCommand('aldeci.scanFile', async (uri?: vscode.Uri) => {
    const target = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (!target) {
      vscode.window.showWarningMessage('ALDECI: No file selected to scan.');
      return;
    }
    await scanFile(target, diagnosticProvider);
  });

  // Command: scan entire workspace
  const scanWorkspaceCmd = vscode.commands.registerCommand('aldeci.scanWorkspace', async () => {
    await scanWorkspace(diagnosticProvider);
  });

  // Command: open dashboard webview
  const openDashboardCmd = vscode.commands.registerCommand('aldeci.openDashboard', () => {
    openDashboard(context);
  });

  context.subscriptions.push(scanFileCmd, scanWorkspaceCmd, openDashboardCmd);

  // Auto-scan on save (if API key configured)
  const onSave = vscode.workspace.onDidSaveTextDocument(async (doc) => {
    const cfg = vscode.workspace.getConfiguration('aldeci');
    const apiKey = cfg.get<string>('apiKey', '');
    if (apiKey && doc.uri.scheme === 'file') {
      await scanFile(doc.uri, diagnosticProvider);
    }
  });
  context.subscriptions.push(onSave);
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}
