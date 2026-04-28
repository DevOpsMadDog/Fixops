/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for an integration.
 */
export type IntegrationResponse = {
    id: string;
    name: string;
    integration_type: string;
    status: string;
    config: Record<string, any>;
    last_sync_at: (string | null);
    last_sync_status: (string | null);
    created_at: string;
    updated_at: string;
};

