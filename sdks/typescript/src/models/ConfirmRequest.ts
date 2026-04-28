/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ConfirmRequest = {
    /**
     * Username/email of person who rotated
     */
    rotated_by: string;
    /**
     * SHA-256 hash of the new secret (not the value itself)
     */
    new_secret_hash?: (string | null);
};

