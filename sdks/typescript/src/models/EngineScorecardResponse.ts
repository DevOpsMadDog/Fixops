/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Engine-generated vendor scorecard.
 */
export type EngineScorecardResponse = {
    vendor_id: string;
    vendor_name: string;
    overall_score: number;
    risk_level: string;
    grade: string;
    domain_score: number;
    cve_score: number;
    breach_score: number;
    data_handling_score: number;
    fourth_party_score: number;
    findings_count: number;
    critical_findings: number;
    calculated_at: string;
    recommendations: Array<string>;
};

