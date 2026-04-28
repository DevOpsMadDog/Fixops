/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type QuotaResponse = {
    org_id: string;
    tier: string;
    requests_per_minute: number;
    requests_per_hour: number;
    requests_per_day: number;
    burst_limit: number;
    current_usage: Record<string, any>;
};

