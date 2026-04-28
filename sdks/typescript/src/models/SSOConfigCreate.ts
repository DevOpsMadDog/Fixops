/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AuthProvider } from './AuthProvider';
import type { SSOStatus } from './SSOStatus';
/**
 * Request model for creating SSO configuration.
 */
export type SSOConfigCreate = {
    name: string;
    provider: AuthProvider;
    status?: SSOStatus;
    metadata?: Record<string, any>;
    entity_id?: (string | null);
    sso_url?: (string | null);
    certificate?: (string | null);
};

