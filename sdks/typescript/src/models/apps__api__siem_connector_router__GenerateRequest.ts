/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__siem_connector_router__GenerateRequest = {
    /**
     * Number of tenants to generate for
     */
    tenants?: number;
    /**
     * Events per tenant (10-20 typical)
     */
    events_per_tenant?: number;
    /**
     * RNG seed for deterministic output
     */
    seed?: number;
};

