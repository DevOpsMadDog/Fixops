/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Result of a re-prioritization run.
 */
export type PrioritizationSummary = {
    org_id: string;
    vulns_evaluated: number;
    epss_refreshed: number;
    duration_ms: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    triggered_at?: string;
};

