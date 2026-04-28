/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a step result.
 */
export type apps__api__playbook_routes__StepResultResponse = {
    step_id: string;
    step_type: string;
    status: string;
    output: Record<string, any>;
    error?: (string | null);
    started_at: string;
    completed_at?: (string | null);
    duration_seconds: number;
};

