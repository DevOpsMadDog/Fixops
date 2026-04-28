/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterDomainRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the maturity domain
     */
    domain_name: string;
    /**
     * Domain category
     */
    domain_type?: string;
    /**
     * Target maturity level (1-5)
     */
    target_level?: number;
};

