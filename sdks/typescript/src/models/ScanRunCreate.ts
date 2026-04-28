/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanRunCreate = {
    scan_type?: string;
    tool?: string;
    status?: string;
    started_at?: (string | null);
    completed_at?: (string | null);
    findings_count?: number;
    critical_count?: number;
    high_count?: number;
};

