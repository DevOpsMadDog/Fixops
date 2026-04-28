/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SSOStatus } from './SSOStatus';
/**
 * Request model for updating SSO configuration.
 */
export type SSOConfigUpdate = {
    name?: (string | null);
    status?: (SSOStatus | null);
    metadata?: (Record<string, any> | null);
    entity_id?: (string | null);
    sso_url?: (string | null);
    certificate?: (string | null);
};

