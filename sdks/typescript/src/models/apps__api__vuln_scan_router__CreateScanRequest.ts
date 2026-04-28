/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__vuln_scan_router__CreateScanRequest = {
    /**
     * Descriptive scan name
     */
    scan_name: string;
    /**
     * nessus | qualys | rapid7 | openvas | nuclei | trivy | grype | custom
     */
    scanner_type?: string;
    /**
     * Scan target (IP, CIDR, hostname, URL)
     */
    target: string;
    /**
     * pending | running | completed | failed | cancelled
     */
    scan_status?: string;
    started_at?: (string | null);
    scanner_version?: (string | null);
};

