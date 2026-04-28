/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__rbac_router__AssignRoleRequest = {
    /**
     * User identifier
     */
    user_id: string;
    /**
     * Role name to assign
     */
    role: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Who is assigning the role
     */
    assigned_by?: string;
};

