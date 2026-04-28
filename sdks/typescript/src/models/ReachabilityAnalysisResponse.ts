/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from reachability analysis.
 */
export type ReachabilityAnalysisResponse = {
    /**
     * Job ID for async analysis
     */
    job_id?: (string | null);
    /**
     * Analysis status
     */
    status: string;
    /**
     * Analysis result
     */
    result?: (Record<string, any> | null);
    /**
     * Status message
     */
    message?: (string | null);
    /**
     * Analysis creation timestamp
     */
    created_at: string;
};

