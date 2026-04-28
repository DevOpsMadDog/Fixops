/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Job status response.
 */
export type risk__reachability__api__JobStatusResponse = {
    job_id: string;
    status: string;
    progress?: number;
    result?: (Record<string, any> | null);
    error?: (string | null);
    created_at: string;
    started_at?: (string | null);
    completed_at?: (string | null);
    estimated_completion?: (string | null);
};

