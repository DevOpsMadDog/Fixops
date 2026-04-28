/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_security_mgmt_router__RegisterApiRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * API endpoint path e.g. /api/users
     */
    endpoint_path: string;
    /**
     * HTTP method
     */
    http_method?: string;
    /**
     * Service or microservice name
     */
    service_name?: string;
    /**
     * Whether auth is required
     */
    authentication_required?: boolean;
    /**
     * Rate limit per minute
     */
    rate_limit_per_minute?: number;
    /**
     * Whether endpoint is publicly accessible
     */
    is_public?: boolean;
    /**
     * one of: public/internal/sensitive/critical
     */
    sensitivity_level?: string;
    /**
     * Manual risk score 0-10
     */
    risk_score?: number;
};

