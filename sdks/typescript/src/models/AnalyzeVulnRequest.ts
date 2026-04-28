/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for vulnerability analysis.
 */
export type AnalyzeVulnRequest = {
    cve_id?: (string | null);
    finding_id?: (string | null);
    description?: (string | null);
    include_threat_intel?: boolean;
    include_epss?: boolean;
    include_kev?: boolean;
};

