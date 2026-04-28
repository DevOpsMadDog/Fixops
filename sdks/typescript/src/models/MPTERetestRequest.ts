/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for POST /api/v1/verify/mpte-retest.
 *
 * Re-runs only the MPTE exploit simulation against the fixed code.
 */
export type MPTERetestRequest = {
    original_code: string;
    fixed_code: string;
    language: string;
    finding_type: string;
    finding_id?: string;
};

