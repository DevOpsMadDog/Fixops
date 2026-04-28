/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GeoBlockRuleRequest = {
    org_id?: string;
    /**
     * ISO 3166-1 alpha-2 country code to block
     */
    country_code: string;
    /**
     * Reason for blocking
     */
    reason?: string;
    /**
     * Severity: low, medium, high, critical
     */
    severity?: string;
};

