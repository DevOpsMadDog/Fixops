/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to add a supply chain vulnerability.
 */
export type AddSupplyChainVulnRequest = {
    vuln_id: string;
    ecosystem: string;
    package_name: string;
    affected_versions?: (string | null);
    patched_versions?: (string | null);
    severity?: string;
    cvss_score?: (number | null);
    reachable?: (boolean | null);
    transitive?: boolean;
    source?: (string | null);
};

