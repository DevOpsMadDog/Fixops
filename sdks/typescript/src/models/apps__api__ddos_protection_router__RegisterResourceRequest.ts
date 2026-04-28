/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ddos_protection_router__RegisterResourceRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Friendly name for the resource
     */
    name: string;
    /**
     * IP address or fully-qualified domain name
     */
    ip_or_fqdn: string;
    /**
     * web | api | dns | network
     */
    resource_type: string;
    /**
     * basic | standard | premium
     */
    protection_tier?: string;
};

