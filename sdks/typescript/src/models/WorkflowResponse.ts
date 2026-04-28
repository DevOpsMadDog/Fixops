/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a workflow.
 */
export type WorkflowResponse = {
    id: string;
    name: string;
    description: string;
    steps: Array<Record<string, any>>;
    triggers: Record<string, any>;
    enabled: boolean;
    created_by: (string | null);
    created_at: string;
    updated_at: string;
};

