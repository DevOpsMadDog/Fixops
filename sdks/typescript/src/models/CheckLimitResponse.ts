/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CheckLimitResponse = {
    allowed: boolean;
    denied_reason: (string | null);
    org_id: string;
    tier: string;
    remaining_minute: number;
    remaining_hour: number;
    remaining_day: number;
    limit_minute: number;
    limit_hour: number;
    limit_day: number;
    burst_limit: number;
};

