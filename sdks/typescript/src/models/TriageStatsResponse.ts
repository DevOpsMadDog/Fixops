/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for /stats.
 */
export type TriageStatsResponse = {
    total_triaged: number;
    analyst_agreement_rate: number;
    average_triage_time_hours: (number | null);
    false_positive_rate: number;
    verdict_breakdown: Record<string, number>;
    trending: Record<string, any>;
    timestamp: string;
};

