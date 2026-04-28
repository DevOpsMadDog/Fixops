/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateDecoyRequest = {
    /**
     * Human-readable decoy name
     */
    name: string;
    /**
     * honeypot | honeytoken | honeydoc | fake_service | canary_endpoint
     */
    decoy_type?: string;
    /**
     * Decoy IP address
     */
    ip_address?: string;
    /**
     * Decoy port number
     */
    port?: number;
    description?: string;
    active?: boolean;
};

