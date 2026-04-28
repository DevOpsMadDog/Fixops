/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__forensics_readiness_router__CreatePlanRequest = {
    org_id?: string;
    /**
     * Plan name
     */
    name: string;
    /**
     * Type of incident
     */
    incident_type: string;
    /**
     * low/medium/high/critical
     */
    priority: string;
    /**
     * List of source IDs
     */
    target_sources?: Array<string>;
    /**
     * Collection procedure steps
     */
    collection_steps?: Array<string>;
};

