/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RewardStatus } from './RewardStatus';
export type RewardRecord = {
    id?: string;
    submission_id: string;
    reporter_id: string;
    program_id: string;
    amount: number;
    bonus_amount?: number;
    status?: RewardStatus;
    currency?: string;
    created_at?: string;
    approved_at?: (string | null);
    paid_at?: (string | null);
    notes?: string;
    org_id?: string;
};

