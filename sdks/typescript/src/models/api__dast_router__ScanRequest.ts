/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__dast_router__AuthConfigRequest } from './apps__api__dast_router__AuthConfigRequest';
export type api__dast_router__ScanRequest = {
    target_url: string;
    profile?: string;
    auth?: (apps__api__dast_router__AuthConfigRequest | null);
    max_depth?: number;
    max_urls?: number;
    requests_per_second?: number;
    timeout?: number;
    respect_robots_txt?: boolean;
    scope_pattern?: string;
    custom_headers?: (Record<string, string> | null);
    openapi_spec?: (Record<string, any> | null);
};

