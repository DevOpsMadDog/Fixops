/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyType } from './PolicyType';
/**
 * Request body for generating a new policy.
 */
export type GeneratePolicyRequest = {
    type: PolicyType;
    org_id?: string;
    /**
     * Override the default policy title
     */
    custom_title?: (string | null);
    /**
     * Days until next review (default 365)
     */
    review_days?: number;
};

