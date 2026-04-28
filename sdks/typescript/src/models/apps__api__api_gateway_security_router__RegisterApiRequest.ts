/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_gateway_security_router__RegisterApiRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Parent gateway UUID
     */
    gateway_id: string;
    /**
     * API name
     */
    name: string;
    /**
     * API version string
     */
    version?: string;
    /**
     * URL path prefix (e.g. /api/v1/payments)
     */
    path_prefix: string;
    /**
     * api_key | oauth2 | jwt | none
     */
    auth_type?: string;
    /**
     * Requests per second rate limit
     */
    rate_limit_rps?: number;
};

