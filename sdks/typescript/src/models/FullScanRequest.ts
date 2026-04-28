/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for triggering a full external risk scan.
 */
export type FullScanRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Primary domain to scan (e.g. acme.io)
     */
    domain: string;
    /**
     * Email domain for credential probe (e.g. acme.io)
     */
    email_domain: string;
};

