/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IntegrationStatus } from './IntegrationStatus';
/**
 * Request model for updating an integration.
 */
export type IntegrationUpdate = {
    name?: (string | null);
    status?: (IntegrationStatus | null);
    config?: (Record<string, any> | null);
};

