/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to queue an outbound sync operation.
 */
export type OutboxRequest = {
    integration_type: string;
    operation: string;
    cluster_id?: (string | null);
    external_id?: (string | null);
    payload: Record<string, any>;
    max_retries?: number;
};

