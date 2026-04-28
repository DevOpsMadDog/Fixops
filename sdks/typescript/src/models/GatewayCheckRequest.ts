/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlanTier } from './PlanTier';
export type GatewayCheckRequest = {
    /**
     * API endpoint path being requested
     */
    endpoint: string;
    /**
     * HTTP method
     */
    method?: string;
    /**
     * Client IP address
     */
    ip: string;
    /**
     * Content-Type header value
     */
    content_type?: (string | null);
    /**
     * Request body size in bytes
     */
    payload_size_bytes?: number;
    /**
     * API key ID for the request
     */
    api_key_id?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: (string | null);
    /**
     * API version requested
     */
    api_version?: string;
    /**
     * Client plan tier
     */
    plan_tier?: PlanTier;
    /**
     * Fields to validate in payload
     */
    required_fields?: (Array<string> | null);
    /**
     * Parsed request body
     */
    payload_dict?: (Record<string, any> | null);
};

