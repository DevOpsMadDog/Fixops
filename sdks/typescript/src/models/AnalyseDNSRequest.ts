/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AnalyseDNSRequest = {
    /**
     * DNS domain to analyse
     */
    domain: string;
    /**
     * IP of the DNS resolver used
     */
    resolver_ip?: (string | null);
    /**
     * Size of the DNS query payload in bytes
     */
    query_size_bytes?: number;
    org_id?: string;
};

