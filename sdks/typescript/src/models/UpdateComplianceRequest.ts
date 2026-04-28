/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateComplianceRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Compliance score 0-100
     */
    compliance_score: number;
    /**
     * List of compliance issues
     */
    issues?: Array<string>;
};

