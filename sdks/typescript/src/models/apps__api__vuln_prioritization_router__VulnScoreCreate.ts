/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_prioritization_router__VulnScoreCreate = {
    cve_id: string;
    asset_id: string;
    asset_criticality?: string;
    cvss_score?: number;
    epss_score?: number;
    kev_listed?: boolean;
    exploitability?: string;
    exposure?: string;
};

