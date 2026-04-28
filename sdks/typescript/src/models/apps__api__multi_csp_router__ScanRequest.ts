/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__multi_csp_router__ScanRequest = {
    /**
     * Provider name: aws|azure|gcp|oci|alibaba|ibm
     */
    provider: string;
    /**
     * Cloud account identifier
     */
    account_id: string;
    org_id?: string;
};

