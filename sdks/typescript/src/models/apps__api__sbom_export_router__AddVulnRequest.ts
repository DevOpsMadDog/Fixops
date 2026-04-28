/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__sbom_export_router__AddVulnRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * CVE identifier
     */
    cve_id: string;
    /**
     * critical|high|medium|low|informational
     */
    severity: string;
    /**
     * CVSS score
     */
    cvss_score?: number;
    /**
     * Affected version string
     */
    affects_version?: string;
    /**
     * Version where fix is available
     */
    fixed_in?: string;
};

