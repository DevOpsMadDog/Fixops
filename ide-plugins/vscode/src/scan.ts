import * as vscode from 'vscode';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';

export interface AldeciScanFinding {
  line: number;        // 1-based
  column?: number;     // 1-based, optional
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  rule_id?: string;
  cwe?: string;
}

export interface AldeciScanResponse {
  scan_id: string;
  file_path: string;
  findings: AldeciScanFinding[];
  scanner: string;
  duration_ms: number;
}

export interface AldeciWorkspaceScanResponse {
  scan_id: string;
  files_scanned: number;
  total_findings: number;
  findings_by_file: Record<string, AldeciScanFinding[]>;
}

function getConfig(): { apiUrl: string; apiKey: string } {
  const cfg = vscode.workspace.getConfiguration('aldeci');
  return {
    apiUrl: cfg.get<string>('apiUrl', 'http://localhost:8000').replace(/\/$/, ''),
    apiKey: cfg.get<string>('apiKey', ''),
  };
}

function severityToDiagnostic(severity: AldeciScanFinding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function postJson<T>(urlStr: string, apiKey: string, body: object): Promise<T> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const payload = JSON.stringify(body);
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-API-Key': apiKey,
        'Authorization': `Bearer ${apiKey}`,
      },
    };
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data) as T);
          } catch (e) {
            reject(new Error(`ALDECI: failed to parse response — ${data}`));
          }
        } else {
          reject(new Error(`ALDECI API returned HTTP ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

export class AldeciDiagnosticProvider {
  constructor(
    private readonly collection: vscode.DiagnosticCollection,
    private readonly statusBar: vscode.StatusBarItem,
  ) {}

  setScanning(label: string): void {
    this.statusBar.text = `$(sync~spin) ALDECI: ${label}`;
  }

  setIdle(findingCount: number): void {
    if (findingCount > 0) {
      this.statusBar.text = `$(shield) ALDECI: ${findingCount} finding${findingCount !== 1 ? 's' : ''}`;
      this.statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      this.statusBar.text = '$(shield) ALDECI: clean';
      this.statusBar.backgroundColor = undefined;
    }
  }

  applyFindings(uri: vscode.Uri, findings: AldeciScanFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
      const line = Math.max(0, f.line - 1);
      const col = Math.max(0, (f.column ?? 1) - 1);
      const range = new vscode.Range(line, col, line, col + 80);
      const diag = new vscode.Diagnostic(
        range,
        `[ALDECI ${f.severity.toUpperCase()}] ${f.title} — ${f.description}`,
        severityToDiagnostic(f.severity),
      );
      diag.source = 'aldeci';
      if (f.rule_id) { diag.code = f.rule_id; }
      return diag;
    });
    this.collection.set(uri, diagnostics);
  }

  clearFile(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }

  clearAll(): void {
    this.collection.clear();
  }
}

export async function scanFile(
  uri: vscode.Uri,
  provider: AldeciDiagnosticProvider,
): Promise<void> {
  const { apiUrl, apiKey } = getConfig();
  if (!apiKey) {
    vscode.window.showErrorMessage('ALDECI: Set aldeci.apiKey in settings before scanning.');
    return;
  }

  const filePath = uri.fsPath;
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    vscode.window.showErrorMessage(`ALDECI: Cannot read file ${filePath}`);
    return;
  }

  provider.setScanning(vscode.workspace.asRelativePath(uri));

  try {
    const resp = await postJson<AldeciScanResponse>(
      `${apiUrl}/api/v1/scan/file`,
      apiKey,
      { file_path: filePath, content, language: detectLanguage(filePath) },
    );
    provider.applyFindings(uri, resp.findings);
    provider.setIdle(resp.findings.length);

    if (resp.findings.length === 0) {
      vscode.window.showInformationMessage(`ALDECI: No findings in ${vscode.workspace.asRelativePath(uri)}.`);
    } else {
      vscode.window.showWarningMessage(
        `ALDECI: ${resp.findings.length} finding(s) in ${vscode.workspace.asRelativePath(uri)}. Check Problems panel.`,
      );
    }
  } catch (err) {
    provider.setIdle(0);
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`ALDECI scan failed: ${msg}`);
  }
}

export async function scanWorkspace(provider: AldeciDiagnosticProvider): Promise<void> {
  const { apiUrl, apiKey } = getConfig();
  if (!apiKey) {
    vscode.window.showErrorMessage('ALDECI: Set aldeci.apiKey in settings before scanning.');
    return;
  }

  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) {
    vscode.window.showWarningMessage('ALDECI: No workspace folder open.');
    return;
  }

  provider.setScanning('workspace');
  provider.clearAll();

  try {
    const resp = await postJson<AldeciWorkspaceScanResponse>(
      `${apiUrl}/api/v1/scan/workspace`,
      apiKey,
      { workspace_path: workspaceRoot },
    );

    let total = 0;
    for (const [filePath, findings] of Object.entries(resp.findings_by_file)) {
      const uri = vscode.Uri.file(filePath);
      provider.applyFindings(uri, findings);
      total += findings.length;
    }
    provider.setIdle(total);

    vscode.window.showInformationMessage(
      `ALDECI workspace scan: ${resp.files_scanned} file(s) scanned, ${total} finding(s) found.`,
    );
  } catch (err) {
    provider.setIdle(0);
    const msg = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`ALDECI workspace scan failed: ${msg}`);
  }
}

function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    py: 'python', ts: 'typescript', tsx: 'typescript',
    js: 'javascript', jsx: 'javascript', java: 'java',
    go: 'go', rs: 'rust', rb: 'ruby', php: 'php',
    cs: 'csharp', cpp: 'cpp', c: 'c', kt: 'kotlin',
    swift: 'swift', sh: 'bash', tf: 'terraform', yaml: 'yaml', yml: 'yaml',
  };
  return map[ext] ?? 'unknown';
}
