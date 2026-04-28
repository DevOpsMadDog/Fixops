/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request payload for POST /api/v1/connectors/dast/scan.
 */
export type DastScanRequest = {
    /**
     * Tenant ID
     */
    org_id: string;
    /**
     * Target URL (http/https). Example: http://localhost:3001
     */
    target: string;
    /**
     * Subset of {'nuclei','zap'} to run.
     */
    scanners?: Array<string>;
    /**
     * If true, high/critical findings are forwarded into the bug-bounty workflow.
     */
    mirror_to_bug_bounty?: boolean;
    /**
     * Per-scanner hard timeout in seconds (30..3600).
     */
    timeout_per_scanner?: number;
};

