/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__iac_scanner_router__ScanRequest = {
    /**
     * Raw IaC file content to scan
     */
    content?: (string | null);
    /**
     * Filename hint for format detection
     */
    filename?: string;
    /**
     * Path to a directory with IaC files
     */
    repo_path?: (string | null);
    /**
     * Optional scan correlation ID
     */
    scan_id?: (string | null);
};

