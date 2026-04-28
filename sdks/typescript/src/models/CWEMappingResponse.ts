/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for CWE→CVE mapping lookup.
 */
export type CWEMappingResponse = {
    /**
     * Normalized CWE ID (e.g. CWE-89)
     */
    cwe_id: string;
    /**
     * Known CVE IDs associated with this CWE
     */
    cves: Array<string>;
    /**
     * Number of matched CVEs
     */
    count: number;
};

