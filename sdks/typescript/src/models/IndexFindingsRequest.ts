/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Index one or more findings from any ALDECI security engine.
 */
export type IndexFindingsRequest = {
    /**
     * List of finding dicts. Each must include 'engine' key.
     */
    findings: Array<Record<string, any>>;
    /**
     * Tenant org ID
     */
    org_id?: (string | null);
    /**
     * If true, use batch indexer with dedup/merge. If false, index individually.
     */
    batch?: boolean;
};

