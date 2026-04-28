/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single finding to enrich.
 */
export type TriageFindingInput = {
    /**
     * Unique finding identifier
     */
    finding_id: string;
    /**
     * Finding title
     */
    title: string;
    /**
     * Severity: critical, high, medium, low, info
     */
    severity: string;
    /**
     * CVE identifier (e.g. CVE-2024-1234)
     */
    cve_id?: (string | null);
    /**
     * CWE identifiers
     */
    cwe_ids?: (Array<string> | null);
    /**
     * Affected asset
     */
    asset_name?: (string | null);
    /**
     * Scanner source
     */
    source?: (string | null);
    /**
     * Numeric risk score 0-100
     */
    risk_score?: (number | null);
};

