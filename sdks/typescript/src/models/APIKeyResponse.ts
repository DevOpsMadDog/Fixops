/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Safe key response — no key_hash exposed.
 */
export type APIKeyResponse = {
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
};

