/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for POST /api/v1/connectors/ingest.
 */
export type IngestResult = {
    /**
     * Unique ID for this ingest batch
     */
    ingest_id: string;
    /**
     * Connector source name
     */
    source: string;
    /**
     * When ingest was processed
     */
    timestamp: string;
    /**
     * Number of findings accepted
     */
    accepted_count: number;
    /**
     * Number of duplicates skipped
     */
    duplicate_count: number;
    /**
     * Number of parsing errors
     */
    error_count: number;
    /**
     * Error details
     */
    errors?: Array<Record<string, any>>;
    /**
     * Background pipeline job ID
     */
    job_id: string;
};

