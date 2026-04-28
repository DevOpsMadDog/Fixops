/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRemediationPlanRequest = {
    /**
     * Control gap ID to remediate
     */
    gap_id: string;
    /**
     * Remediation plan description
     */
    plan_description: string;
    /**
     * Owner responsible for remediation
     */
    owner: string;
    /**
     * Target completion date (ISO)
     */
    target_date: string;
};

