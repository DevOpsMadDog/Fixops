/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for scanning a single file.
 */
export type apps__api__semgrep_router__ScanFileRequest = {
    /**
     * Absolute or relative path to the file
     */
    file_path: string;
    /**
     * Semgrep ruleset or config
     */
    rules?: (string | null);
    /**
     * Organisation identifier
     */
    org_id?: string;
};

