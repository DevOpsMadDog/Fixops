/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /{id}/rotate endpoint.
 */
export type apps__api__secret_scanner_router__RotateRequest = {
    /**
     * Email/username of person who rotated the secret
     */
    rotated_by: string;
    /**
     * First chars of the replacement key (optional)
     */
    new_key_prefix?: (string | null);
};

