/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssessmentIn = {
    policy_id: string;
    mfa_score?: number;
    backup_score?: number;
    incident_response_score?: number;
    patch_score?: number;
    training_score?: number;
    recommendations?: Array<string>;
    assessed_at?: (string | null);
};

