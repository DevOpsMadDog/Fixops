/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type VulnContext = {
    /**
     * Asset criticality: critical | high | medium | low
     */
    asset_criticality?: string;
    internet_exposed?: boolean;
    has_known_exploit?: boolean;
    epss_score?: number;
    cvss_base?: number;
    /**
     * CISA Known Exploited Vulnerability
     */
    kev?: boolean;
};

