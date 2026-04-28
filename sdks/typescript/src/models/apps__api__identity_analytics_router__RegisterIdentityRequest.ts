/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__identity_analytics_router__RegisterIdentityRequest = {
    username: string;
    email?: string;
    department?: string;
    job_title?: string;
    identity_type?: string;
    privileged?: boolean;
    mfa_enabled?: boolean;
    last_login?: (string | null);
    login_count?: number;
    failed_logins?: number;
};

