/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DeduplicateRequest = {
    /**
     * List of finding dicts to deduplicate
     */
    findings: Array<Record<string, any>>;
    /**
     * Tenant / org identifier
     */
    org_id?: string;
    /**
     * Levenshtein ratio threshold for fuzzy title matching (0-1)
     */
    fuzzy_threshold?: number;
};

