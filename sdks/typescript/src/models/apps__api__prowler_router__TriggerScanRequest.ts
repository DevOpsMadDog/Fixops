/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__prowler_router__TriggerScanRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Cloud provider: aws/azure/gcp
     */
    provider?: string;
    /**
     * Cloud account/subscription ID
     */
    account_id?: string;
    /**
     * Comma-separated regions to scan
     */
    regions?: string;
    /**
     * Specific checks to run
     */
    checks?: (Array<string> | null);
    /**
     * Scan timeout in seconds
     */
    timeout?: number;
};

