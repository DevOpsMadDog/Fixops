/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__iam_policy_router__PolicyCreate = {
    /**
     * Human-readable policy name
     */
    policy_name: string;
    /**
     * aws_iam / azure_rbac / gcp_iam
     */
    policy_type?: string;
    /**
     * user / group / service_account / role
     */
    principal_type?: string;
    /**
     * Principal identifier (ARN, email, etc.)
     */
    principal_id?: string;
    /**
     * List of permission actions
     */
    permissions?: Array<string>;
    /**
     * List of resource ARNs / URIs
     */
    resources?: Array<string>;
    /**
     * Policy conditions
     */
    conditions?: Record<string, any>;
    /**
     * Whether this is a managed (vs inline) policy
     */
    is_managed?: boolean;
};

