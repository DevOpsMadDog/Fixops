/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SIEMTargetConfigure = {
    org_id?: string;
    name: string;
    /**
     * splunk_hec | sentinel | generic
     */
    siem_type: string;
    /**
     * Connector-specific config (url, token, tenant_id, etc.)
     */
    config?: Record<string, any>;
};

