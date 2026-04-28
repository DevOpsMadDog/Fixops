/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MatchCriteria } from './MatchCriteria';
export type apps__api__exception_policy_router__AddRuleRequest = {
    name: string;
    description?: string;
    criteria: MatchCriteria;
    /**
     * suppress | downgrade | defer
     */
    action: string;
    downgrade_to?: (string | null);
    defer_days?: (number | null);
    expires_at?: (string | null);
    enabled?: boolean;
    created_by?: string;
};

