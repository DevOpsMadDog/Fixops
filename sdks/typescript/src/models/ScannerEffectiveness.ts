/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Effectiveness metrics for a single scanner.
 */
export type ScannerEffectiveness = {
    /**
     * Scanner/source identifier
     */
    scanner_name: string;
    /**
     * Total findings produced
     */
    findings_count?: number;
    /**
     * Fraction of findings confirmed true-positive
     */
    true_positive_rate?: number;
    /**
     * Average numeric severity weight (0-10)
     */
    avg_severity?: number;
    /**
     * Number of unique CVE IDs found
     */
    unique_cves?: number;
};

