/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to enrich findings with vulnerability intelligence.
 */
export type EnrichFindingsRequest = {
    findings: Array<Record<string, any>>;
    /**
     * Target region for geo-weighted scoring
     */
    target_region?: (string | null);
};

