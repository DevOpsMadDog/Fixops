/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RewardStatus } from './RewardStatus';
export type UpdateRewardRequest = {
    /**
     * New reward status
     */
    status: RewardStatus;
    /**
     * Bonus amount on top of base reward (USD)
     */
    bonus_amount?: number;
    /**
     * Reward notes (payment reference, justification, etc.)
     */
    notes?: string;
};

