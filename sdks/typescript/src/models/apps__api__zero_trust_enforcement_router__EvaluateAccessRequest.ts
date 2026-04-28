/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_enforcement_router__EvaluateAccessRequest = {
    principal_id: string;
    principal_type?: string;
    resource_id: string;
    resource_type?: string;
    action_requested?: string;
    source_ip?: string;
    device_trust_score?: number;
    user_trust_score?: number;
    mfa_verified?: boolean;
    location?: string;
    device_type?: string;
};

