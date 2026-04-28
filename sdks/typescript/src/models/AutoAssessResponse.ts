/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Automated vendor risk assessment result.
 */
export type AutoAssessResponse = {
    vendor_id: string;
    name: string;
    domain: (string | null);
    risk_score: number;
    risk_level: string;
    findings: Array<Record<string, any>>;
    last_assessed: string;
    recommendations: Array<string>;
    cves: Array<Record<string, any>>;
    breach_matches: Array<Record<string, any>>;
};

