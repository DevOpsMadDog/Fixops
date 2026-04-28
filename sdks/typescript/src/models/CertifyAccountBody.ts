/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CertifyAccountBody = {
    /**
     * Certifier user ID
     */
    certified_by: string;
    /**
     * approved | revoked | suspended
     */
    decision: string;
    /**
     * Certification justification
     */
    justification?: string;
    /**
     * Next certification date ISO
     */
    next_certification?: string;
};

