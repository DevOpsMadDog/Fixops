/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__patch_prioritizer_router__ScoreRequest = {
    /**
     * CVE identifier, e.g. CVE-2021-44228
     */
    cve_id: string;
    /**
     * CVSS base score 0-10
     */
    cvss_score?: number;
    /**
     * EPSS probability 0-1
     */
    epss_score?: number;
    /**
     * Asset criticality: low|medium|high|critical
     */
    asset_criticality?: string;
};

