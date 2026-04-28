/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single finding submitted for ATT&CK mapping.
 */
export type apps__api__mitre_coverage_router__FindingItem = {
    /**
     * Finding ID
     */
    id?: (string | null);
    /**
     * Finding title
     */
    title: string;
    /**
     * Finding description
     */
    description?: (string | null);
    /**
     * CWE ID (e.g. 'CWE-89', '89', 89)
     */
    cwe_id?: null;
    /**
     * critical/high/medium/low/info
     */
    severity?: (string | null);
};

