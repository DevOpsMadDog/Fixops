/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyStatus } from './PolicyStatus';
/**
 * Request model for creating a policy.
 */
export type apps__api__policies_router__PolicyCreate = {
    name: string;
    description: string;
    /**
     * Policy type (guardrail, compliance, custom)
     */
    policy_type: string;
    status?: PolicyStatus;
    rules?: Record<string, any>;
    metadata?: Record<string, any>;
};

