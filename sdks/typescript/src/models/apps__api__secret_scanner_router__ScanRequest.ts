/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /scan endpoint.
 */
export type apps__api__secret_scanner_router__ScanRequest = {
    /**
     * Raw text content to scan
     */
    text?: (string | null);
    /**
     * Git diff text (only added lines scanned)
     */
    diff?: (string | null);
    /**
     * Logical file path for attribution
     */
    file_path?: string;
    /**
     * Commit SHA for attribution
     */
    commit_sha?: (string | null);
    /**
     * Author for attribution
     */
    author?: (string | null);
    /**
     * Treat input as git diff (scan only + lines)
     */
    is_diff?: boolean;
};

