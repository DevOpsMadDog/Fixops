/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for enriching a single finding.
 */
export type EnrichRequest = {
    /**
     * Raw scanner finding dict. Recognized fields: cwe_id, cve_id, severity, cvss, remediation. All other fields are preserved in original_finding.
     */
    finding: Record<string, any>;
};

