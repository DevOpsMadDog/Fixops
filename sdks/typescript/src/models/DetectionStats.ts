/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Aggregate statistics for an org's insider-threat programme.
 */
export type DetectionStats = {
    org_id: string;
    total_activities: number;
    total_alerts: number;
    reviewed_alerts: number;
    pending_alerts: number;
    risk_distribution: Record<string, number>;
    top_indicators: Record<string, number>;
};

