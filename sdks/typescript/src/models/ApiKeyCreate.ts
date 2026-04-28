/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ApiKeyCreate = {
    key_name: string;
    owner_id?: string;
    scopes?: Array<string>;
    rate_limit_per_hour?: number;
    expires_at?: (string | null);
};

