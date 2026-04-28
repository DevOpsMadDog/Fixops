/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single security finding from a scanner.
 */
export type api__mitre_mapper_router__FindingInput = {
    /**
     * Finding ID
     */
    id?: (string | null);
    /**
     * Finding title or name
     */
    title: string;
    /**
     * Finding description
     */
    description?: (string | null);
    /**
     * Severity: critical, high, medium, low, info
     */
    severity?: (string | null);
    /**
     * CWE ID (e.g., 'CWE-89', '89', 89, 'cwe-89')
     */
    cwe_id?: null;
    /**
     * List of CVE IDs (e.g., ['CVE-2021-44228'])
     */
    cve_ids?: (Array<string> | null);
    /**
     * Single CVE ID (alias for cve_ids)
     */
    cve_id?: (string | null);
};

