/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for bulk accept risk.
 */
export type BulkAcceptRiskRequest = {
    ids: Array<string>;
    justification: string;
    approved_by: string;
    expiry_days?: (number | null);
};

