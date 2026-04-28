/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__api_security_engine_router__EndpointCreate = {
    endpoint_path: string;
    http_method?: string;
    service_name?: string;
    authentication_required?: boolean;
    rate_limit_per_minute?: number;
    is_public?: boolean;
    sensitivity_level?: string;
    risk_score?: number;
};

