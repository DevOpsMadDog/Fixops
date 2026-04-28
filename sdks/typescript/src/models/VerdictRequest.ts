/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type VerdictRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Analyst ID issuing the verdict
     */
    analyst_id: string;
    /**
     * confirmed | disputed | closed
     */
    verdict: string;
    /**
     * Optional analyst notes
     */
    notes?: string;
};

