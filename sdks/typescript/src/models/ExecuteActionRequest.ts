/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to execute an agent action.
 */
export type ExecuteActionRequest = {
    /**
     * Type of action to execute
     */
    action_type: string;
    parameters?: Record<string, any>;
    /**
     * Execute asynchronously
     */
    async_execution?: boolean;
};

