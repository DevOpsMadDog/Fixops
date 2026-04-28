/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for attack chain prediction.
 */
export type AttackChainRequest = {
    /**
     * CVE identifier
     */
    cve_id: string;
    /**
     * CVSS score (0-10)
     */
    cvss_score?: number;
    /**
     * Whether an exploit is available
     */
    has_exploit?: boolean;
    /**
     * Whether vulnerability is network-accessible
     */
    is_network_exposed?: boolean;
};

