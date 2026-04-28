/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for scanning a directory.
 */
export type ScanDirectoryRequest = {
    /**
     * Absolute or relative filesystem path to scan
     */
    path: string;
    /**
     * Semgrep ruleset or config, e.g. p/security-audit. Defaults to p/default.
     */
    rules?: (string | null);
    /**
     * Organisation identifier
     */
    org_id?: string;
};

