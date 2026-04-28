/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__data_retention__DataCategory } from './core__data_retention__DataCategory';
/**
 * Request body for creating or updating a retention policy.
 */
export type RetentionPolicyRequest = {
    category: core__data_retention__DataCategory;
    retention_days: number;
    description?: string;
    compliance_framework?: (string | null);
    enabled?: boolean;
};

