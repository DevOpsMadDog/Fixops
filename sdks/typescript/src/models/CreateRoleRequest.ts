/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRoleRequest = {
    /**
     * Unique role name
     */
    role_name: string;
    /**
     * business | technical | privileged | service-account | emergency
     */
    role_type: string;
    /**
     * List of permission strings
     */
    permissions?: Array<string>;
    /**
     * Role owner
     */
    owner?: string;
    /**
     * critical | high | medium | low
     */
    risk_level?: string;
};

