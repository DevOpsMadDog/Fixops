/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RaspMode } from './RaspMode';
import type { RateLimitConfig } from './RateLimitConfig';
import type { ThreatCategory } from './ThreatCategory';
/**
 * Full RASP engine configuration.
 */
export type RaspConfig = {
    mode?: RaspMode;
    honeypot_url?: string;
    rate_limit?: RateLimitConfig;
    max_body_inspect_bytes?: number;
    inspect_request_body?: boolean;
    inspect_headers?: boolean;
    inspect_query_params?: boolean;
    trusted_ips?: Array<string>;
    enabled_categories?: Array<ThreatCategory>;
};

