/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Session response model.
 */
export type apps__api__session_router__SessionResponse = {
    id: string;
    user_email: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
    last_active: string;
    expires_at: string;
    is_active: boolean;
    org_id: string;
    metadata: Record<string, any>;
};

