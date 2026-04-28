/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterAccountBody = {
    /**
     * Account username
     */
    username: string;
    /**
     * service_account | admin | root | domain_admin | database_admin | application_account | shared
     */
    account_type?: string;
    /**
     * Target system name
     */
    system_name?: string;
    /**
     * Owning department
     */
    department?: string;
    /**
     * Account owner
     */
    owner?: string;
    /**
     * MFA status
     */
    mfa_enabled?: boolean;
};

