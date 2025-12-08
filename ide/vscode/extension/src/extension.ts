/**
 * FixOps VS Code Extension
 * Real-time vulnerability detection and remediation
 */

import * as vscode from 'vscode';
import { FixOpsClient } from './fixopsClient';
import { VulnerabilityProvider } from './vulnerabilityProvider';
import { DiagnosticManager } from './diagnosticManager';

let fixopsClient: FixOpsClient;
let vulnerabilityProvider: VulnerabilityProvider;
let diagnosticManager: DiagnosticManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('FixOps extension is now active');

    // Initialize FixOps client
    const config = vscode.workspace.getConfiguration('fixops');
    const apiUrl = config.get<string>('apiUrl', 'https://api.fixops.com');
    const apiKey = config.get<string>('apiKey', '');

    if (!apiKey) {
        vscode.window.showWarningMessage('FixOps API key not configured. Please set fixops.apiKey');
    }

    fixopsClient = new FixOpsClient(apiUrl, apiKey);
    vulnerabilityProvider = new VulnerabilityProvider(fixopsClient);
    diagnosticManager = new DiagnosticManager(context, fixopsClient);

    // Register commands
    const scanCommand = vscode.commands.registerCommand('fixops.scan', async () => {
        await scanWorkspace();
    });

    const scanFileCommand = vscode.commands.registerCommand('fixops.scanFile', async (uri: vscode.Uri) => {
        await scanFile(uri);
    });

    const fixCommand = vscode.commands.registerCommand('fixops.fix', async (vulnerability: any) => {
        await fixVulnerability(vulnerability);
    });

    const showIssuesCommand = vscode.commands.registerCommand('fixops.showIssues', () => {
        vulnerabilityProvider.refresh();
    });

    context.subscriptions.push(scanCommand, scanFileCommand, fixCommand, showIssuesCommand);

    // Register tree view
    const treeView = vscode.window.createTreeView('fixopsVulnerabilities', {
        treeDataProvider: vulnerabilityProvider,
        showCollapseAll: true,
    });

    context.subscriptions.push(treeView);

    // Real-time scanning
    if (config.get<boolean>('enableRealTime', true)) {
        setupRealTimeScanning(context);
    }

    // Register diagnostics
    diagnosticManager.initialize();
}

async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "FixOps: Scanning workspace",
        cancellable: false,
    }, async (progress) => {
        try {
            progress.report({ increment: 0, message: "Starting scan..." });
            
            const results = await fixopsClient.scanWorkspace(workspaceFolders[0].uri.fsPath);
            
            progress.report({ increment: 100, message: "Scan complete" });
            
            vulnerabilityProvider.updateResults(results);
            diagnosticManager.updateDiagnostics(results);
            
            vscode.window.showInformationMessage(
                `FixOps: Found ${results.vulnerabilities.length} vulnerabilities`
            );
        } catch (error: any) {
            vscode.window.showErrorMessage(`FixOps scan failed: ${error.message}`);
        }
    });
}

async function scanFile(uri: vscode.Uri) {
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `FixOps: Scanning ${uri.fsPath}`,
        cancellable: false,
    }, async (progress) => {
        try {
            const results = await fixopsClient.scanFile(uri.fsPath);
            diagnosticManager.updateDiagnostics(results);
            vscode.window.showInformationMessage(
                `FixOps: Found ${results.vulnerabilities.length} vulnerabilities in file`
            );
        } catch (error: any) {
            vscode.window.showErrorMessage(`FixOps scan failed: ${error.message}`);
        }
    });
}

async function fixVulnerability(vulnerability: any) {
    try {
        const fix = await fixopsClient.getFix(vulnerability.id);
        
        if (fix && fix.suggestedFix) {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const range = new vscode.Range(
                    vulnerability.line - 1,
                    0,
                    vulnerability.line - 1,
                    Number.MAX_VALUE
                );
                
                await editor.edit(editBuilder => {
                    editBuilder.replace(range, fix.suggestedFix);
                });
                
                vscode.window.showInformationMessage('FixOps: Applied fix');
            }
        } else {
            vscode.window.showInformationMessage('FixOps: No automated fix available');
        }
    } catch (error: any) {
        vscode.window.showErrorMessage(`FixOps fix failed: ${error.message}`);
    }
}

function setupRealTimeScanning(context: vscode.ExtensionContext) {
    // Watch for file changes
    const watcher = vscode.workspace.createFileSystemWatcher('**/*.{py,js,ts,java,go,rb,php}');
    
    watcher.onDidChange(async (uri) => {
        // Debounce rapid changes
        setTimeout(async () => {
            await scanFile(uri);
        }, 1000);
    });
    
    context.subscriptions.push(watcher);
}

export function deactivate() {
    diagnosticManager.dispose();
}
