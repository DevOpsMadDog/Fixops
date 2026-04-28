/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after indexing findings.
 */
export type IndexFindingsResponse = {
    indexed: number;
    entity_ids: Array<string>;
    deduplicated?: number;
    merged?: number;
    failed?: number;
    errors?: Array<string>;
    status: string;
};

