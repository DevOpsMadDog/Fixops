/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MgrScanRequest = {
    /**
     * Absolute path to repo or file to scan
     */
    target_path: string;
    /**
     * filesystem | git_history
     */
    scan_type?: string;
    /**
     * Also scan git commit history
     */
    include_git_history?: boolean;
};

