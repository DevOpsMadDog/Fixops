/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for root cause identification.
 */
export type RootCauseRequest = {
    /**
     * SecurityFactor symptom to trace back from
     */
    symptom?: string;
    /**
     * Map of SecurityFactor names to their boolean state
     */
    evidence?: Record<string, boolean>;
};

