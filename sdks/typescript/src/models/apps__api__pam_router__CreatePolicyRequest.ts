/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__pam_router__CreatePolicyRequest = {
    name: string;
    require_approval?: boolean;
    max_session_minutes?: number;
    allowed_hours?: Array<any>;
    mfa_required?: boolean;
    recording_required?: boolean;
};

