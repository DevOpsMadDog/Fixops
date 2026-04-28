/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Filters for listing findings.
 */
export type FindingListFilter = {
    /**
     * Filter by severity
     */
    severity?: (Array<string> | null);
    /**
     * Filter by status
     */
    status?: (Array<string> | null);
    /**
     * Filter by source connector
     */
    connector?: (string | null);
    /**
     * Filter by CVE ID
     */
    cve_id?: (string | null);
    /**
     * Filter by asset ID
     */
    asset_id?: (string | null);
    /**
     * Filter by assignee
     */
    assigned_to?: (string | null);
    /**
     * Created after (ISO 8601)
     */
    date_from?: (string | null);
    /**
     * Created before (ISO 8601)
     */
    date_to?: (string | null);
};

