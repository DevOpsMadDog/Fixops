/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__unified_issues_router__DiffRequest = {
    /**
     * Prior scan to compare against
     */
    baseline_scan_id: string;
    /**
     * Scan being diffed
     */
    current_scan_id: string;
};

