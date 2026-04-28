/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Simplified simulation from CVSS score.
 */
export type CVSSSimulationRequest = {
    /**
     * CVSS score
     */
    cvss_score: number;
    /**
     * Asset value ($)
     */
    asset_value?: number;
    has_exploit?: boolean;
    is_internet_facing?: boolean;
    /**
     * Industry vertical
     */
    industry?: string;
    iterations?: number;
};

