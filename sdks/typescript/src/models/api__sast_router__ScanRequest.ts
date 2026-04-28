/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Unified scan request — provide either repo_path or file_list.
 */
export type api__sast_router__ScanRequest = {
    /**
     * Absolute path to the repository root to scan
     */
    repo_path?: (string | null);
    /**
     * Explicit list of file paths to scan
     */
    file_list?: (Array<string> | null);
    /**
     * Skip files whose content hash is unchanged since last scan
     */
    incremental?: boolean;
};

