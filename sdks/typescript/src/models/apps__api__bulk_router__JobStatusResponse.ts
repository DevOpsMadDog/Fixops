/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for job status.
 */
export type apps__api__bulk_router__JobStatusResponse = {
    job_id: string;
    status: string;
    action_type: string;
    total_items: number;
    processed_items: number;
    success_count: number;
    failure_count: number;
    progress_percent: number;
    started_at: string;
    completed_at?: (string | null);
    results?: null;
    errors?: Array<Record<string, any>>;
};

