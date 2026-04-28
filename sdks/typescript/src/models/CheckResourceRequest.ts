/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__config_drift__CloudProvider } from './core__config_drift__CloudProvider';
export type CheckResourceRequest = {
    /**
     * Unique identifier of the resource
     */
    resource_id: string;
    /**
     * Resource type (e.g. s3_bucket, iam_user)
     */
    resource_type: string;
    /**
     * Current resource configuration
     */
    actual_config: Record<string, any>;
    /**
     * Cloud provider
     */
    provider: core__config_drift__CloudProvider;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

