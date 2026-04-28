/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create a new API key.
 */
export type KeyCreateRequest = {
    name: string;
    user_id: string;
    role?: string;
    scopes?: Array<any>;
    ttl_days?: (number | null);
};

