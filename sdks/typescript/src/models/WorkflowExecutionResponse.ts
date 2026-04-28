/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a workflow execution.
 */
export type WorkflowExecutionResponse = {
    id: string;
    workflow_id: string;
    status: string;
    triggered_by: (string | null);
    input_data: Record<string, any>;
    output_data: Record<string, any>;
    error_message: (string | null);
    started_at: string;
    completed_at: (string | null);
};

