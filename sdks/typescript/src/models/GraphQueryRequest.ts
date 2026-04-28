/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GraphQueryRequest = {
    org_id: string;
    query_text: string;
    target_cores?: Array<number>;
    max_results?: number;
    include_relationships?: boolean;
    confidence_threshold?: number;
};

