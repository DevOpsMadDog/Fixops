/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanCreateRequest = {
    app_id: string;
    scan_type?: string;
    tool: string;
    status?: string;
    findings_count?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    started_at?: (string | null);
    completed_at?: (string | null);
};

