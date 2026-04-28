/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to generate a fix for a finding.
 *
 * Accepts either a full 'finding' dict or individual fields (finding_id, title, severity, cve_id).
 */
export type api__autofix_router__GenerateFixRequest = {
    /**
     * Finding dict with id, title, severity, cve_ids, cwe_id, etc.
     */
    finding?: (Record<string, any> | null);
    /**
     * Finding ID (shorthand)
     */
    finding_id?: (string | null);
    /**
     * Finding title (shorthand)
     */
    title?: (string | null);
    /**
     * Finding severity (shorthand)
     */
    severity?: (string | null);
    /**
     * CVE ID (shorthand)
     */
    cve_id?: (string | null);
    /**
     * Language hint (python, java, etc.)
     */
    language?: (string | null);
    /**
     * Fix type (patch, config, upgrade)
     */
    fix_type?: (string | null);
    /**
     * Source code surrounding the vulnerability
     */
    source_code?: (string | null);
    /**
     * Repo metadata (language, framework, etc.)
     */
    repo_context?: (Record<string, any> | null);
};

