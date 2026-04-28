/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__policy_router__PolicyCreate = {
    name: string;
    description?: string;
    scope: string;
    language?: string;
    rules?: Array<Record<string, any>>;
    decision_on_match?: string;
    enabled?: boolean;
    org_id?: string;
};

