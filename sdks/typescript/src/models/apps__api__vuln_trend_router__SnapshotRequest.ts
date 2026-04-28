/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_trend_router__SnapshotRequest = {
    total_vulns?: (number | null);
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    mttr_days?: number;
    new_this_week?: number;
    resolved_this_week?: number;
    sla_breached?: number;
    taken_at?: (string | null);
};

