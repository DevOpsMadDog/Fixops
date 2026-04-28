/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ProgramScope } from './ProgramScope';
import type { ProgramStatus } from './ProgramStatus';
import type { RewardTier } from './RewardTier';
export type BountyProgram = {
    id?: string;
    name: string;
    description?: string;
    status?: ProgramStatus;
    scope?: ProgramScope;
    reward_tiers?: Record<string, RewardTier>;
    /**
     * Safe harbor policy text
     */
    safe_harbor?: string;
    /**
     * Full legal terms and conditions
     */
    legal_terms?: string;
    /**
     * Monthly budget cap (USD)
     */
    monthly_budget?: number;
    org_id?: string;
    created_at?: string;
    updated_at?: string;
    total_rewards_paid?: number;
    submission_count?: number;
};

