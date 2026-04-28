/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_scanner_router__CreateFindingRequest = {
    result_id: string;
    asset_ip?: string;
    asset_hostname?: string;
    vuln_name: string;
    cve_id?: string;
    cvss_score?: number;
    severity?: string;
    plugin_id?: string;
    description?: string;
    solution?: string;
    status?: string;
};

