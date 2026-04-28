/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * CVE-specific risk quantification.
 */
export type api__monte_carlo_router__CVERiskRequest = {
    cve_id: string;
    cvss_score: number;
    epss_score?: number;
    kev_listed?: boolean;
    asset_value?: number;
    is_reachable?: boolean;
};

