/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_governance_router__ViolationCreate = {
    policy_id: string;
    resource_id: string;
    resource_type: string;
    violation_details?: string;
    /**
     * low/medium/high/critical
     */
    severity?: string;
};

