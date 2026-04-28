/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssignVulnIn = {
    /**
     * Asset ID
     */
    asset_id: string;
    /**
     * CVE identifier e.g. CVE-2024-1234
     */
    cve_id: string;
    /**
     * CVSS score 0-10
     */
    cvss_score?: number;
    /**
     * EPSS probability 0-1
     */
    epss_score?: number;
    /**
     * Whether in CISA KEV catalog
     */
    kev_listed?: boolean;
    /**
     * low|medium|high|critical
     */
    exploitability?: string;
    /**
     * unpatched|partial|patched
     */
    patch_status?: string;
    /**
     * immediate|high|medium|low|scheduled
     */
    priority?: string;
};

