/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from key creation — includes the plaintext key (shown ONCE).
 */
export type KeyCreateResponse = {
    id: string;
    key_prefix: string;
    name: string;
    user_id: string;
    role: string;
    scopes: Array<any>;
    is_active: boolean;
    created_at: string;
    expires_at?: (string | null);
    rotated_at?: (string | null);
    revoked_at?: (string | null);
    last_used_at?: (string | null);
    predecessor_id?: (string | null);
    plaintext_key: string;
};

