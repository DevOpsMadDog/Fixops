/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAccessPolicyRequest = {
    /**
     * Policy name
     */
    name: string;
    /**
     * file | api | database | network | application | service
     */
    resource_type: string;
    /**
     * read | write | execute | delete | admin
     */
    action: string;
    /**
     * allow | deny
     */
    effect?: string;
    /**
     * Optional policy conditions
     */
    conditions?: (Record<string, any> | null);
};

