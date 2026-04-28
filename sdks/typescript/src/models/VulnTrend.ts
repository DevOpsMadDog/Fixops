/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vulnerability backlog trend data point.
 */
export type VulnTrend = {
    org_id: string;
    period_start: string;
    period_end: string;
    new_vulns: number;
    resolved_vulns: number;
    total_open: number;
    mean_time_to_remediate_hours?: (number | null);
    sla_breach_rate: number;
    risk_debt_score: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
};

