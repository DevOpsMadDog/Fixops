/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Forensic timeline build request.
 */
export type TimelineRequest = {
    /**
     * FTS5-compatible search query
     */
    query: string;
    start: string;
    end: string;
    limit?: number;
    org_id?: (string | null);
};

