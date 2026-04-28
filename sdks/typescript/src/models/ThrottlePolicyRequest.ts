/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ThrottlePolicyRequest = {
    /**
     * API key ID or IP address to throttle
     */
    target_id: string;
    /**
     * 'api_key' or 'ip'
     */
    target_type?: string;
    /**
     * Max requests in 10-second burst window
     */
    burst_limit: number;
    /**
     * Max requests in 60-second sustained window
     */
    sustained_limit: number;
    requests_per_minute: number;
    requests_per_hour: number;
    description?: string;
};

