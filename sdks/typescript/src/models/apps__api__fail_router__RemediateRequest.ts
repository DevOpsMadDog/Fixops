/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to mark a drill finding as remediated.
 */
export type apps__api__fail_router__RemediateRequest = {
    /**
     * Who remediated the finding
     */
    remediated_by?: (string | null);
    /**
     * Notes about remediation
     */
    remediation_note?: string;
};

