/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__data_retention__DataCategory } from './core__data_retention__DataCategory';
/**
 * Configurable retention policy for a data category.
 */
export type RetentionPolicy = {
    id?: string;
    category: core__data_retention__DataCategory;
    retention_days: number;
    description?: string;
    compliance_framework?: (string | null);
    enabled?: boolean;
    org_id?: string;
};

