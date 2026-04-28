/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AccessLevel } from './AccessLevel';
import type { core__access_matrix__ResourceType } from './core__access_matrix__ResourceType';
export type apps__api__access_matrix_router__GrantAccessRequest = {
    /**
     * ALDECI role name
     */
    role: string;
    resource_type: core__access_matrix__ResourceType;
    access_level: AccessLevel;
    /**
     * None = all resources of type
     */
    resource_id?: (string | null);
    conditions?: Record<string, any>;
    org_id?: string;
};

