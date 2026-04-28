/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateScanResultRequest = {
    schedule_id?: (string | null);
    scanner_id: string;
    scan_start?: (string | null);
    scan_end?: (string | null);
    assets_scanned?: number;
    total_findings?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    status?: string;
};

