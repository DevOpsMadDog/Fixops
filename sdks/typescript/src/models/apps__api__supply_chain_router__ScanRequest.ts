/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for triggering a repository dependency scan.
 */
export type apps__api__supply_chain_router__ScanRequest = {
    /**
     * Git repository URL to scan
     */
    repo_url: string;
    /**
     * Branch to scan
     */
    branch?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

