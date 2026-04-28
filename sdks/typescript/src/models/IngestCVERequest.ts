/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Validated CVE ingest request.
 */
export type IngestCVERequest = {
    cve_id: string;
    org_id?: (string | null);
    severity?: (string | null);
    cvss_score?: (number | null);
    description?: (string | null);
};

