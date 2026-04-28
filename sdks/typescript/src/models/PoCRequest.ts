/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for PoC verification.
 */
export type PoCRequest = {
    /**
     * Script language: python, bash, nodejs, curl, go
     */
    language?: string;
    /**
     * PoC script code
     */
    code: string;
    /**
     * CVE identifier
     */
    cve_id?: string;
    /**
     * Target URL for network-based PoCs
     */
    target_url?: string;
    /**
     * Strings expected in output if exploitable
     */
    expected_indicators?: Array<string>;
    timeout_seconds?: number;
    requires_network?: boolean;
    finding_id?: string;
};

