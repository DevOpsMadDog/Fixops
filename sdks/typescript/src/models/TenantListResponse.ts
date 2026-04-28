/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for the tenant list endpoint.
 */
export type TenantListResponse = {
    /**
     * List of org_id strings
     */
    tenants: Array<string>;
    /**
     * Total number of tenants
     */
    count: number;
};

