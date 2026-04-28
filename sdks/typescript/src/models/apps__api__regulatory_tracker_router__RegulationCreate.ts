/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for adding a regulation.
 */
export type apps__api__regulatory_tracker_router__RegulationCreate = {
    /**
     * e.g. GDPR, PCI-DSS, NIS2
     */
    framework: string;
    title: string;
    description?: string;
    /**
     * ISO-8601 date e.g. 2024-03-31
     */
    effective_date: string;
    /**
     * high | medium | low
     */
    impact: string;
    affected_controls?: Array<string>;
    /**
     * upcoming | active | superseded
     */
    status?: string;
};

