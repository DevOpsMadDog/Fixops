/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_dependency_risk_router__AddVulnRequest = {
    org_id?: string;
    /**
     * CVE identifier
     */
    cve_id: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * CVSS base score
     */
    cvss_score: number;
    /**
     * Version that fixes the vuln
     */
    fixed_version?: string;
};

