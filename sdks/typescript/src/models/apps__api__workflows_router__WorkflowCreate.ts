/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for creating a workflow.
 */
export type apps__api__workflows_router__WorkflowCreate = {
    name: string;
    /**
     * Workflow description
     */
    description?: string;
    steps?: Array<Record<string, any>>;
    triggers?: Record<string, any>;
    enabled?: boolean;
};

