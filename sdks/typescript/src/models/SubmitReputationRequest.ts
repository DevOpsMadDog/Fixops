/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SubmitReputationRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * IP address
     */
    ip: string;
    /**
     * Reputation score 0-100 (lower = worse reputation)
     */
    reputation_score?: number;
    /**
     * Threat categories: spam, botnet, proxy, tor, scanner, malware
     */
    categories?: Array<string>;
    /**
     * Data source / feed name
     */
    source?: string;
};

