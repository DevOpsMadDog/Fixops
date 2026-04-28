/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IntegrationCategory } from './IntegrationCategory';
/**
 * Request body for registering a custom/private integration.
 */
export type RegisterCustomAppRequest = {
    /**
     * Unique slug for this app
     */
    id: string;
    name: string;
    description: string;
    category: IntegrationCategory;
    version?: string;
    author: string;
    icon_url?: (string | null);
    config_schema?: Record<string, any>;
    required_scopes?: Array<string>;
};

