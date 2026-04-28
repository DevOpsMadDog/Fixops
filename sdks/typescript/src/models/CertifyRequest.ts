/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for submitting a certification decision.
 */
export type CertifyRequest = {
    /**
     * One of: 'certify', 'revoke', 'escalate'
     */
    decision: string;
    /**
     * Free-text reason for the decision
     */
    justification?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

