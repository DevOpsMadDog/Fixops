/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ProvisionAccountBody = {
    /**
     * Unique username for the account
     */
    username: string;
    /**
     * Human-readable display name
     */
    display_name?: string;
    /**
     * Email address
     */
    email?: string;
    /**
     * employee | contractor | service | system | bot | vendor | temp
     */
    account_type?: string;
    /**
     * Department or team
     */
    department?: string;
    /**
     * Manager username or ID
     */
    manager?: string;
};

