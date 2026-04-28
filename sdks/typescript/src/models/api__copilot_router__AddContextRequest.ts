/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to add context to a session.
 */
export type api__copilot_router__AddContextRequest = {
    /**
     * Type of context (cve, asset, finding)
     */
    context_type: string;
    /**
     * Context data
     */
    data: Record<string, any>;
};

