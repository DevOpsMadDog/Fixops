/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Executive summary of findings.
 */
export type apps__api__findings_routes__FindingSummary = {
    total_open: number;
    total_in_progress: number;
    total_remediated: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_connector: Record<string, number>;
    findings_this_week: number;
    findings_this_month: number;
    remediation_rate_7d: number;
    remediation_rate_30d: number;
    average_time_to_remediate_days: number;
};

