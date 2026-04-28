/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vulnerability analysis result.
 */
export type VulnAnalysisResponse = {
    cve_id: (string | null);
    severity: string;
    epss_score: number;
    epss_percentile: number;
    kev_listed: boolean;
    first_seen?: (string | null);
    threat_intel: Record<string, any>;
    attack_vector: string;
    impact_analysis: Record<string, any>;
    recommendation: string;
};

