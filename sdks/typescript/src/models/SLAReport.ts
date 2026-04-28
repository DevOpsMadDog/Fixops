/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Compiled SLA compliance report.
 */
export type SLAReport = {
    org_id: string;
    generated_at: string;
    period_days: number;
    overall_compliance_rate: number;
    by_severity: Record<string, Record<string, any>>;
    by_team: Array<Record<string, any>>;
    by_framework: Record<string, Record<string, any>>;
    by_asset_tier: Record<string, Record<string, any>>;
    escalation_summary: Record<string, number>;
    exception_summary: Record<string, number>;
    leaderboard: Array<Record<string, any>>;
};

