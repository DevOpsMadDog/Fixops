/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for refreshing a session.
 */
export type RefreshSessionRequest = {
    /**
     * New TTL from now (hours). Omit to keep existing expiry.
     */
    ttl_hours?: (number | null);
};

