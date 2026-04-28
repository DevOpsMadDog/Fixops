/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_posture_router__RegisterAccountRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Cloud provider account/subscription ID
     */
    account_id: string;
    /**
     * Human-readable account name
     */
    account_name?: string;
    /**
     * Cloud provider: aws, azure, gcp, alibaba, oracle, ibm
     */
    provider?: string;
    /**
     * Primary region
     */
    region?: string;
    /**
     * Number of resources in account
     */
    resource_count?: number;
    /**
     * Account status
     */
    status?: string;
};

