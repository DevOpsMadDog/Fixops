/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * EPSS score for a single CVE.
 */
export type EPSSScore = {
    cve_id: string;
    /**
     * Probability of exploitation in 30 days
     */
    epss: number;
    /**
     * Percentile rank among all CVEs
     */
    percentile: number;
    model_version?: string;
    score_date?: string;
    cached?: boolean;
};

