/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MgrPolicyResponse = {
    id: string;
    name: string;
    description: string;
    categories: Array<string>;
    max_age_days: number;
    require_rotation: boolean;
    block_on_commit: boolean;
    compliance_frameworks: Array<string>;
    created_at: string;
};

