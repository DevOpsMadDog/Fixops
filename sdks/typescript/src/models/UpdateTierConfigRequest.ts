/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlanTier } from './PlanTier';
export type UpdateTierConfigRequest = {
    tier: PlanTier;
    requests_per_minute: number;
    requests_per_hour: number;
    burst_limit: number;
    sustained_limit: number;
};

