/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__bug_bounty__Severity } from './core__bug_bounty__Severity';
export type RewardTier = {
    severity: core__bug_bounty__Severity;
    /**
     * Minimum reward amount (USD)
     */
    min_reward: number;
    /**
     * Maximum reward amount (USD)
     */
    max_reward: number;
    bonus_eligible?: boolean;
};

