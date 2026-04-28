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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const scan_1 = require("./scan");
const dashboard_1 = require("./dashboard");
let statusBarItem;
let diagnosticCollection;
function activate(context) {
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
    const diagnosticProvider = new scan_1.AldeciDiagnosticProvider(diagnosticCollection, statusBarItem);
    // Command: scan active/selected file
    const scanFileCmd = vscode.commands.registerCommand('aldeci.scanFile', async (uri) => {
        const target = uri ?? vscode.window.activeTextEditor?.document.uri;
        if (!target) {
            vscode.window.showWarningMessage('ALDECI: No file selected to scan.');
            return;
        }
        await (0, scan_1.scanFile)(target, diagnosticProvider);
    });
    // Command: scan entire workspace
    const scanWorkspaceCmd = vscode.commands.registerCommand('aldeci.scanWorkspace', async () => {
        await (0, scan_1.scanWorkspace)(diagnosticProvider);
    });
    // Command: open dashboard webview
    const openDashboardCmd = vscode.commands.registerCommand('aldeci.openDashboard', () => {
        (0, dashboard_1.openDashboard)(context);
    });
    context.subscriptions.push(scanFileCmd, scanWorkspaceCmd, openDashboardCmd);
    // Auto-scan on save (if API key configured)
    const onSave = vscode.workspace.onDidSaveTextDocument(async (doc) => {
        const cfg = vscode.workspace.getConfiguration('aldeci');
        const apiKey = cfg.get('apiKey', '');
        if (apiKey && doc.uri.scheme === 'file') {
            await (0, scan_1.scanFile)(doc.uri, diagnosticProvider);
        }
    });
    context.subscriptions.push(onSave);
}
function deactivate() {
    diagnosticCollection?.dispose();
    statusBarItem?.dispose();
}
//# sourceMappingURL=extension.js.map