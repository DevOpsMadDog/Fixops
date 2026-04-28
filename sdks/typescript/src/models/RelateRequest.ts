/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Create relationship request.
 */
export type RelateRequest = {
    source_id: string;
    target_id: string;
    rel_type: string;
    confidence?: (number | null);
    properties?: (Record<string, any> | null);
};

