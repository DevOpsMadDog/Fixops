/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RateLimitTier } from './RateLimitTier';
/**
 * Body for updating an endpoint tier mapping or per-key override.
 */
export type EndpointConfigUpdate = {
    /**
     * Regex pattern for the endpoint path (e.g. '^/api/v1/custom').
     */
    path_pattern?: (string | null);
    /**
     * Rate limit tier to assign to the path pattern.
     */
    tier?: (RateLimitTier | null);
    /**
     * API key ID to apply a per-key request-per-minute override.
     */
    api_key_id?: (string | null);
    /**
     * Requests per minute for the per-key override. 0 removes override.
     */
    requests_per_minute?: (number | null);
};

