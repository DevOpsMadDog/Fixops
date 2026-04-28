/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ReportDNSRebindingRequest = {
    /**
     * Public domain that was resolved
     */
    domain: string;
    /**
     * IP address the domain resolved to
     */
    resolved_ip: string;
    org_id?: string;
};

