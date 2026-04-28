/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for creating a new session.
 */
export type apps__api__session_router__CreateSessionRequest = {
    /**
     * User email address
     */
    user_email: string;
    /**
     * Client IP address
     */
    ip_address: string;
    /**
     * Client user agent string
     */
    user_agent: string;
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Session TTL in hours
     */
    ttl_hours?: number;
    /**
     * Optional metadata
     */
    metadata?: Record<string, any>;
};

