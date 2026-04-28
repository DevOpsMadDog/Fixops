/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__casb_router__RecordViolationRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * ID of the violated policy
     */
    policy_id: string;
    /**
     * User who triggered the violation
     */
    user: string;
    /**
     * App involved in the violation
     */
    app_name: string;
    /**
     * Detailed description of violation
     */
    violation_detail?: string;
    /**
     * Severity: critical/high/medium/low/info
     */
    severity?: string;
};

