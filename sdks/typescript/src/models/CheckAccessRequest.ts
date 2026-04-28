/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__access_matrix__ResourceType } from './core__access_matrix__ResourceType';
export type CheckAccessRequest = {
    user_role: string;
    resource_type: core__access_matrix__ResourceType;
    resource_id?: (string | null);
    org_id?: string;
};

