/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__software_license_security_router__CreatePolicyRequest = {
    org_id?: string;
    policy_name: string;
    allowed_licenses?: Array<string>;
    blocked_licenses?: Array<string>;
    require_approval?: boolean;
};

