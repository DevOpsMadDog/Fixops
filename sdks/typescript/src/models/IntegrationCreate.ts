/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IntegrationStatus } from './IntegrationStatus';
import type { IntegrationType } from './IntegrationType';
/**
 * Request model for creating an integration.
 */
export type IntegrationCreate = {
    name: string;
    integration_type: IntegrationType;
    status?: IntegrationStatus;
    config?: Record<string, any>;
};

