/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MgrScanSummaryResponse = {
    scan_id: string;
    scan_type: string;
    target_path: string;
    files_scanned: number;
    commits_scanned: number;
    findings_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    started_at: string;
    completed_at: (string | null);
    errors: Array<string>;
};

