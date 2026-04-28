/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vendor scorecard with all component scores and trend.
 */
export type ScorecardResponse = {
    vendor_id: string;
    vendor_name: string;
    tier: string;
    overall_score: number;
    grade: string;
    questionnaire_score: number;
    monitoring_score: number;
    contract_score: number;
    incident_score: number;
    active_risks: number;
    contract_gaps: number;
    score_trend: Array<Record<string, any>>;
    calculated_at: string;
};

