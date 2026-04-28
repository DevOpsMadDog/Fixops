/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CloseEventRequest = {
    org_id?: string;
    /**
     * true_positive/false_positive/benign
     */
    verdict: string;
    /**
     * Resolution description
     */
    resolution?: string;
};

