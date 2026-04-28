/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for the current tenant info endpoint.
 */
export type CurrentTenantResponse = {
    /**
     * Current request org_id
     */
    org_id: string;
    /**
     * True if org_id is 'default' (dev mode)
     */
    is_default: boolean;
};

