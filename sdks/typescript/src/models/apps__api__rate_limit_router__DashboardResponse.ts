/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__rate_limit_router__DashboardResponse = {
    org_id: string;
    tracked_keys: number;
    top_consumers: Array<Record<string, any>>;
    endpoint_tiers: Array<Record<string, any>>;
    per_key_overrides: Record<string, number>;
};

