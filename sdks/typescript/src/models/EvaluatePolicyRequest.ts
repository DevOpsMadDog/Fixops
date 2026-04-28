/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Re-evaluate a list of package scan results against a given policy.
 */
export type EvaluatePolicyRequest = {
    packages: Array<Record<string, string>>;
    policy: Record<string, any>;
    org_id?: string;
};

