/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from bulk update.
 */
export type BulkStatusUpdateResponse = {
    updated: number;
    failed: number;
    total_requested: number;
    errors: Array<string>;
};

