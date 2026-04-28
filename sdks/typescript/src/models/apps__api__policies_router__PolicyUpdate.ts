/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyStatus } from './PolicyStatus';
/**
 * Request model for updating a policy.
 */
export type apps__api__policies_router__PolicyUpdate = {
    name?: (string | null);
    description?: (string | null);
    policy_type?: (string | null);
    status?: (PolicyStatus | null);
    rules?: (Record<string, any> | null);
    metadata?: (Record<string, any> | null);
};

