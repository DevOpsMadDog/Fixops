/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for POST /reconcile.
 */
export type ReconcileRequest = {
    /**
     * Tenant org identifier
     */
    org_id?: string;
    /**
     * The previous scan run id
     */
    prior_scan_id: string;
    /**
     * The current scan run id
     */
    current_scan_id: string;
};

