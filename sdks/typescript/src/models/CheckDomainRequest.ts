/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CheckDomainRequest = {
    /**
     * Domain to probe
     */
    domain: string;
    /**
     * TLS port (default 443)
     */
    port?: number;
    /**
     * Socket timeout in seconds
     */
    timeout?: number;
};

