/**
 * FixOps API Client for VS Code Extension
 */

import axios, { AxiosInstance } from 'axios';
import * as fs from 'fs';
import * as path from 'path';

export interface Vulnerability {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    file: string;
    line: number;
    column: number;
    message: string;
    ruleId: string;
    cveId?: string;
    fixable: boolean;
}

export interface ScanResults {
    vulnerabilities: Vulnerability[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

export interface Fix {
    id: string;
    suggestedFix: string;
    confidence: number;
    explanation: string;
}

export class FixOpsClient {
    private client: AxiosInstance;

    constructor(apiUrl: string, apiKey: string) {
        this.client = axios.create({
            baseURL: apiUrl,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json',
            },
            timeout: 30000,
        });
    }

    async scanWorkspace(workspacePath: string): Promise<ScanResults> {
        // Scan all code files in workspace
        const files = this.findCodeFiles(workspacePath);
        
        const vulnerabilities: Vulnerability[] = [];
        
        for (const file of files) {
            const fileResults = await this.scanFile(file);
            vulnerabilities.push(...fileResults.vulnerabilities);
        }
        
        return {
            vulnerabilities,
            summary: this.calculateSummary(vulnerabilities),
        };
    }

    async scanFile(filePath: string): Promise<ScanResults> {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            
            // Call FixOps API
            const response = await this.client.post('/api/v1/scan', {
                file_path: filePath,
                content: content,
            });
            
            return this.formatResults(response.data, filePath);
        } catch (error: any) {
            console.error(`Scan failed for ${filePath}:`, error);
            return {
                vulnerabilities: [],
                summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
            };
        }
    }

    async getFix(vulnerabilityId: string): Promise<Fix | null> {
        try {
            const response = await this.client.get(`/api/v1/fixes/${vulnerabilityId}`);
            return response.data;
        } catch (error) {
            return null;
        }
    }

    private findCodeFiles(rootPath: string): string[] {
        const files: string[] = [];
        const extensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php'];
        
        function walkDir(dir: string) {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                
                // Skip node_modules, venv, etc.
                if (entry.name.startsWith('.') || 
                    entry.name === 'node_modules' || 
                    entry.name === 'venv' ||
                    entry.name === '__pycache__') {
                    continue;
                }
                
                if (entry.isDirectory()) {
                    walkDir(fullPath);
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name);
                    if (extensions.includes(ext)) {
                        files.push(fullPath);
                    }
                }
            }
        }
        
        walkDir(rootPath);
        return files;
    }

    private formatResults(data: any, filePath: string): ScanResults {
        const vulnerabilities: Vulnerability[] = (data.findings || []).map((finding: any) => ({
            id: finding.id || `${filePath}:${finding.line}`,
            severity: finding.severity || 'medium',
            file: filePath,
            line: finding.line || 0,
            column: finding.column || 0,
            message: finding.message || finding.description || 'Security issue detected',
            ruleId: finding.rule_id || finding.ruleId || 'unknown',
            cveId: finding.cve_id || finding.cveId,
            fixable: finding.fixable || false,
        }));
        
        return {
            vulnerabilities,
            summary: this.calculateSummary(vulnerabilities),
        };
    }

    private calculateSummary(vulnerabilities: Vulnerability[]) {
        return {
            total: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === 'critical').length,
            high: vulnerabilities.filter(v => v.severity === 'high').length,
            medium: vulnerabilities.filter(v => v.severity === 'medium').length,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
        };
    }
}
