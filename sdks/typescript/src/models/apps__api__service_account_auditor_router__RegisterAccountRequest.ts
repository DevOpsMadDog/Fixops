/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__service_account_auditor_router__RegisterAccountRequest = {
    /**
     * Organization identifier
     */
    org_id: string;
    /**
     * Service account name or identifier
     */
    name: string;
    /**
     * Platform: k8s, aws, gcp, azure, linux
     */
    system: string;
    /**
     * List of permissions/roles
     */
    permissions?: Array<string>;
    /**
     * Days since last use
     */
    last_used_days_ago?: number;
};

