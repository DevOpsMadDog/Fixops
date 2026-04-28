/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /scan — scan an API from an OpenAPI spec URL or JSON body.
 */
export type apps__api__api_security_router__ScanRequest = {
    target_url?: (string | null);
    openapi_spec?: (Record<string, any> | null);
    headers?: (Record<string, string> | null);
    check_rate_limits?: boolean;
    check_graphql?: boolean;
    max_rate_limit_endpoints?: number;
};

