/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * One-time creation response that includes the plaintext key.
 */
export type CreateKeyResponse = {
    id: string;
    name: string;
    prefix: string;
    org_id: string;
    created_by: string;
    created_at: string;
    expires_at: (string | null);
    last_used_at: (string | null);
    use_count: number;
    rate_limit: number;
    scopes: Array<string>;
    role: string;
    is_active: boolean;
    description: string;
    /**
     * Store this securely — shown only once
     */
    raw_key: string;
};

