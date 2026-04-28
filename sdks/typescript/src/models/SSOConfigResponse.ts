/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for SSO configuration.
 */
export type SSOConfigResponse = {
    id: string;
    name: string;
    provider: string;
    status: string;
    metadata: Record<string, any>;
    entity_id: (string | null);
    sso_url: (string | null);
    certificate: (string | null);
    created_at: string;
    updated_at: string;
};

