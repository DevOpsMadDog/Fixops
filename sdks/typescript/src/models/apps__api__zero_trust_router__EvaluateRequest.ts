/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__zero_trust_router__EvaluateRequest = {
    user_id: string;
    org_id?: string;
    resource?: string;
    device_id?: string;
    device_compliant?: boolean;
    network_ip?: string;
    mfa_verified?: boolean;
    user_risk_score?: number;
    timestamp?: (string | null);
};

