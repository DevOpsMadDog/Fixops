/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__zero_gravity_router__IngestRequest = {
    /**
     * Unique data identifier
     */
    data_id: string;
    /**
     * Data category: evidence, findings, scans, etc.
     */
    category: string;
    /**
     * Data content (string or JSON)
     */
    content: string;
    metadata?: Record<string, any>;
};

