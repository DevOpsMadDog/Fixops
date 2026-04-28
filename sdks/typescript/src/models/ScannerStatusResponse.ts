/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for scanner status.
 */
export type ScannerStatusResponse = {
    checkov_available: boolean;
    tfsec_available: boolean;
    available_scanners: Array<string>;
};

