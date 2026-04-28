/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * API response shape for a policy document.
 */
export type apps__api__policy_generator_router__PolicyResponse = {
    id: string;
    type: string;
    title: string;
    version: string;
    content: string;
    approved_by: (string | null);
    effective_date: (string | null);
    review_date: (string | null);
    status: string;
    org_id: string;
    created_at: string;
    updated_at: string;
};

