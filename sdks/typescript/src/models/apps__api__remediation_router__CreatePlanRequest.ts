/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create a CWE-based remediation plan.
 */
export type apps__api__remediation_router__CreatePlanRequest = {
    id: string;
    cwe_id: string;
    severity?: string;
    title?: (string | null);
};

