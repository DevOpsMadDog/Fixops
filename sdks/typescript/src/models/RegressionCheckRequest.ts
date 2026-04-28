/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for POST /api/v1/verify/regression.
 *
 * Runs only the regression-detection suite (Suite 2) without the
 * full MPTE re-test or dependency check.
 */
export type RegressionCheckRequest = {
    original_code: string;
    fixed_code: string;
    language: string;
    finding_id?: string;
};

