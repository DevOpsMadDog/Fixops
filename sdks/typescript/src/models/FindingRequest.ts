/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A finding to create or sync as a GitHub issue.
 */
export type FindingRequest = {
    /**
     * Unique finding identifier
     */
    finding_id: string;
    /**
     * Short finding title
     */
    title: string;
    /**
     * critical | high | medium | low | informational
     */
    severity: string;
    /**
     * sast | dast | sca | iac | secret | cloud | network
     */
    finding_type?: string;
    /**
     * Full finding description (Markdown)
     */
    description?: string;
    /**
     * CWE identifier, e.g. 'CWE-79'
     */
    cwe?: (string | null);
    /**
     * CVSS score, e.g. 9.8
     */
    cvss?: (number | null);
    /**
     * Source file path
     */
    affected_file?: (string | null);
    /**
     * Line number in affected file
     */
    affected_line?: (number | null);
    /**
     * Remediation guidance (Markdown)
     */
    remediation?: (string | null);
    /**
     * Scanner that found this (semgrep, trivy, etc.)
     */
    scanner?: (string | null);
    /**
     * CVE identifier, e.g. 'CVE-2024-1234'
     */
    cve_id?: (string | null);
    /**
     * open | resolved | in_progress | accepted_risk
     */
    status?: string;
    /**
     * Additional metadata
     */
    extra?: Record<string, any>;
};

