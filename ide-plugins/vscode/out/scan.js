"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.AldeciDiagnosticProvider = void 0;
exports.scanFile = scanFile;
exports.scanWorkspace = scanWorkspace;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const https = __importStar(require("https"));
const http = __importStar(require("http"));
const url_1 = require("url");
function getConfig() {
    const cfg = vscode.workspace.getConfiguration('aldeci');
    return {
        apiUrl: cfg.get('apiUrl', 'http://localhost:8000').replace(/\/$/, ''),
        apiKey: cfg.get('apiKey', ''),
    };
}
function severityToDiagnostic(severity) {
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
function postJson(urlStr, apiKey, body) {
    return new Promise((resolve, reject) => {
        const parsed = new url_1.URL(urlStr);
        const payload = JSON.stringify(body);
        const options = {
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
                        resolve(JSON.parse(data));
                    }
                    catch (e) {
                        reject(new Error(`ALDECI: failed to parse response — ${data}`));
                    }
                }
                else {
                    reject(new Error(`ALDECI API returned HTTP ${res.statusCode}: ${data}`));
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}
class AldeciDiagnosticProvider {
    constructor(collection, statusBar) {
        this.collection = collection;
        this.statusBar = statusBar;
    }
    setScanning(label) {
        this.statusBar.text = `$(sync~spin) ALDECI: ${label}`;
    }
    setIdle(findingCount) {
        if (findingCount > 0) {
            this.statusBar.text = `$(shield) ALDECI: ${findingCount} finding${findingCount !== 1 ? 's' : ''}`;
            this.statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        }
        else {
            this.statusBar.text = '$(shield) ALDECI: clean';
            this.statusBar.backgroundColor = undefined;
        }
    }
    applyFindings(uri, findings) {
        const diagnostics = findings.map((f) => {
            const line = Math.max(0, f.line - 1);
            const col = Math.max(0, (f.column ?? 1) - 1);
            const range = new vscode.Range(line, col, line, col + 80);
            const diag = new vscode.Diagnostic(range, `[ALDECI ${f.severity.toUpperCase()}] ${f.title} — ${f.description}`, severityToDiagnostic(f.severity));
            diag.source = 'aldeci';
            if (f.rule_id) {
                diag.code = f.rule_id;
            }
            return diag;
        });
        this.collection.set(uri, diagnostics);
    }
    clearFile(uri) {
        this.collection.delete(uri);
    }
    clearAll() {
        this.collection.clear();
    }
}
exports.AldeciDiagnosticProvider = AldeciDiagnosticProvider;
async function scanFile(uri, provider) {
    const { apiUrl, apiKey } = getConfig();
    if (!apiKey) {
        vscode.window.showErrorMessage('ALDECI: Set aldeci.apiKey in settings before scanning.');
        return;
    }
    const filePath = uri.fsPath;
    let content;
    try {
        content = fs.readFileSync(filePath, 'utf8');
    }
    catch {
        vscode.window.showErrorMessage(`ALDECI: Cannot read file ${filePath}`);
        return;
    }
    provider.setScanning(vscode.workspace.asRelativePath(uri));
    try {
        const resp = await postJson(`${apiUrl}/api/v1/scan/file`, apiKey, { file_path: filePath, content, language: detectLanguage(filePath) });
        provider.applyFindings(uri, resp.findings);
        provider.setIdle(resp.findings.length);
        if (resp.findings.length === 0) {
            vscode.window.showInformationMessage(`ALDECI: No findings in ${vscode.workspace.asRelativePath(uri)}.`);
        }
        else {
            vscode.window.showWarningMessage(`ALDECI: ${resp.findings.length} finding(s) in ${vscode.workspace.asRelativePath(uri)}. Check Problems panel.`);
        }
    }
    catch (err) {
        provider.setIdle(0);
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`ALDECI scan failed: ${msg}`);
    }
}
async function scanWorkspace(provider) {
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
        const resp = await postJson(`${apiUrl}/api/v1/scan/workspace`, apiKey, { workspace_path: workspaceRoot });
        let total = 0;
        for (const [filePath, findings] of Object.entries(resp.findings_by_file)) {
            const uri = vscode.Uri.file(filePath);
            provider.applyFindings(uri, findings);
            total += findings.length;
        }
        provider.setIdle(total);
        vscode.window.showInformationMessage(`ALDECI workspace scan: ${resp.files_scanned} file(s) scanned, ${total} finding(s) found.`);
    }
    catch (err) {
        provider.setIdle(0);
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`ALDECI workspace scan failed: ${msg}`);
    }
}
function detectLanguage(filePath) {
    const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
    const map = {
        py: 'python', ts: 'typescript', tsx: 'typescript',
        js: 'javascript', jsx: 'javascript', java: 'java',
        go: 'go', rs: 'rust', rb: 'ruby', php: 'php',
        cs: 'csharp', cpp: 'cpp', c: 'c', kt: 'kotlin',
        swift: 'swift', sh: 'bash', tf: 'terraform', yaml: 'yaml', yml: 'yaml',
    };
    return map[ext] ?? 'unknown';
}
//# sourceMappingURL=scan.js.map