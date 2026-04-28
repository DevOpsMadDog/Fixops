/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__connector_routes__FindingSeverity } from './apps__api__connector_routes__FindingSeverity';
/**
 * A finding normalized to ALDECI's canonical format.
 */
export type NormalizedFinding = {
    /**
     * Unique ID from source system
     */
    finding_id: string;
    /**
     * Finding title/summary
     */
    title: string;
    /**
     * Detailed description
     */
    description?: (string | null);
    /**
     * Severity level
     */
    severity: apps__api__connector_routes__FindingSeverity;
    /**
     * CVSS v3 score
     */
    cvss_score?: (number | null);
    /**
     * CVSS v3 vector string
     */
    cvss_vector?: (string | null);
    /**
     * CVE IDs (e.g. CVE-2024-1234)
     */
    cve_ids?: Array<string>;
    /**
     * CWE IDs (e.g. 79, 89)
     */
    cwe_ids?: Array<number>;
    /**
     * Affected component/library
     */
    component?: (string | null);
    /**
     * Component version
     */
    version?: (string | null);
    /**
     * File path in repository
     */
    file_path?: (string | null);
    /**
     * Line number (if applicable)
     */
    line_number?: (number | null);
    /**
     * Remediation guidance
     */
    remediation?: (string | null);
    /**
     * Estimated effort to fix
     */
    remediation_effort?: (string | null);
    /**
     * Mark as false positive
     */
    false_positive?: boolean;
    /**
     * Arbitrary tags
     */
    tags?: Array<string>;
    /**
     * Additional metadata
     */
    metadata?: Record<string, any>;
};

