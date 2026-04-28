/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__policy_enforcement_router__PolicyCreate = {
    name: string;
    /**
     * network/identity/data/endpoint/cloud/application/physical
     */
    policy_domain: string;
    /**
     * mandatory/recommended/prohibited
     */
    policy_type?: string;
    /**
     * automated/manual/hybrid
     */
    enforcement_mechanism?: string;
    content?: string;
};

