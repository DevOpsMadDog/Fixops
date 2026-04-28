/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ResourceStateUpdate = {
    /**
     * running/stopped/terminated/unknown/pending
     */
    state: string;
    /**
     * compliant/non_compliant/unknown/exempt
     */
    compliance_status?: (string | null);
};

