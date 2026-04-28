/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateApiKeyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Human-readable key name
     */
    key_name: string;
    /**
     * Owner user/service ID
     */
    owner_id?: string;
    /**
     * Permission scopes
     */
    scopes?: Array<string>;
    /**
     * Rate limit per hour
     */
    rate_limit_per_hour?: number;
    /**
     * ISO expiry timestamp
     */
    expires_at?: (string | null);
};

