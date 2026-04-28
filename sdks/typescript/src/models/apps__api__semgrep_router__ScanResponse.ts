/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__semgrep_router__ScanResponse = {
    scan_id: string;
    org_id: string;
    target: string;
    rules: string;
    started_at: string;
    completed_at: string;
    status: string;
    is_mock: boolean;
    findings_count: number;
    severity_breakdown: Record<string, number>;
    findings: Array<Record<string, any>>;
    error?: (string | null);
};

