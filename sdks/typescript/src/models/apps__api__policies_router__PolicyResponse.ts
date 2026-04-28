/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a policy.
 */
export type apps__api__policies_router__PolicyResponse = {
    id: string;
    name: string;
    description: string;
    policy_type: string;
    status: string;
    rules: Record<string, any>;
    metadata: Record<string, any>;
    created_by: (string | null);
    created_at: string;
    updated_at: string;
};

