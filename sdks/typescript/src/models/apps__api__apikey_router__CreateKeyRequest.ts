/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__apikey_router__CreateKeyRequest = {
    name: string;
    org_id: string;
    role?: string;
    scopes?: Array<string>;
    expires_at?: (string | null);
    rate_limit?: number;
    description?: string;
};

