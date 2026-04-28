/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /policies/evaluate — evaluate image against runtime policies.
 */
export type PolicyEvaluateRequest = {
    image_ref: string;
    manifest?: (Record<string, any> | null);
    config?: (Record<string, any> | null);
    policy_id?: (string | null);
};

