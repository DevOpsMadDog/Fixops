/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for detector status.
 */
export type SecretsDetectorStatusResponse = {
    gitleaks_available: boolean;
    trufflehog_available: boolean;
    available_scanners: Array<string>;
};

