/**
 * Diagnostic Manager for VS Code - Shows vulnerabilities as diagnostics
 */

import * as vscode from 'vscode';
import { FixOpsClient, ScanResults } from './fixopsClient';

export class DiagnosticManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private disposables: vscode.Disposable[] = [];

    constructor(
        private context: vscode.ExtensionContext,
        private client: FixOpsClient
    ) {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('fixops');
        context.subscriptions.push(this.diagnosticCollection);
    }

    initialize() {
        // Listen for document changes
        const changeSubscription = vscode.workspace.onDidChangeTextDocument(async (event) => {
            if (this.shouldScanFile(event.document.uri)) {
                await this.scanDocument(event.document);
            }
        });

        // Listen for document opens
        const openSubscription = vscode.workspace.onDidOpenTextDocument(async (document) => {
            if (this.shouldScanFile(document.uri)) {
                await this.scanDocument(document);
            }
        });

        this.disposables.push(changeSubscription, openSubscription);
    }

    async updateDiagnostics(results: ScanResults) {
        this.diagnosticCollection.clear();

        // Group vulnerabilities by file
        const byFile = new Map<string, vscode.Diagnostic[]>();

        for (const vuln of results.vulnerabilities) {
            if (!byFile.has(vuln.file)) {
                byFile.set(vuln.file, []);
            }

            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(
                    vuln.line - 1,
                    vuln.column,
                    vuln.line - 1,
                    vuln.column + 100
                ),
                vuln.message,
                this.getSeverity(vuln.severity)
            );

            diagnostic.source = 'FixOps';
            diagnostic.code = vuln.ruleId;
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(
                        vscode.Uri.file(vuln.file),
                        new vscode.Range(vuln.line - 1, 0, vuln.line - 1, 0)
                    ),
                    vuln.cveId ? `CVE: ${vuln.cveId}` : 'Security vulnerability'
                ),
            ];

            byFile.get(vuln.file)!.push(diagnostic);
        }

        // Set diagnostics for each file
        for (const [file, diagnostics] of byFile.entries()) {
            this.diagnosticCollection.set(vscode.Uri.file(file), diagnostics);
        }
    }

    private async scanDocument(document: vscode.TextDocument) {
        try {
            const results = await this.client.scanFile(document.uri.fsPath);
            await this.updateDiagnostics(results);
        } catch (error) {
            // Silently fail for real-time scanning
            console.error('Real-time scan failed:', error);
        }
    }

    private shouldScanFile(uri: vscode.Uri): boolean {
        const ext = uri.fsPath.split('.').pop()?.toLowerCase();
        return ['py', 'js', 'ts', 'java', 'go', 'rb', 'php'].includes(ext || '');
    }

    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
                return vscode.DiagnosticSeverity.Error;
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    dispose() {
        this.disposables.forEach(d => d.dispose());
        this.diagnosticCollection.dispose();
    }
}
