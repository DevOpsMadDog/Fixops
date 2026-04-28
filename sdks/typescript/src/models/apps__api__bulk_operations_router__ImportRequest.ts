/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__bulk_operations_router__ImportRequest = {
    /**
     * Raw file content (CSV, JSON, SARIF, or CycloneDX)
     */
    content: string;
    /**
     * Import format: csv, json, sarif, cyclonedx
     */
    format: string;
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Source label attached to findings
     */
    source?: string;
};

