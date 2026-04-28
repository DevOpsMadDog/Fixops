/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ciem_router__LeastPrivilegeRequest = {
    /**
     * AWS IAM policy document JSON
     */
    policy: Record<string, any>;
    /**
     * Actions actually observed in CloudTrail / usage logs
     */
    used_permissions: Array<string>;
};

