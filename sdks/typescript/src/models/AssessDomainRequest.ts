/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssessDomainRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Current maturity level (1-5)
     */
    current_level: number;
    /**
     * Assessment score (0-100)
     */
    score: number;
    /**
     * Supporting evidence
     */
    evidence?: string;
};

