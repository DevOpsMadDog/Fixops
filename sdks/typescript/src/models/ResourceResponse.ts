/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ResourceResponse = {
    resource_id: string;
    provider: string;
    resource_type: string;
    name: string;
    region: string;
    account_id: string;
    tags?: Record<string, string>;
    public_exposure?: boolean;
    security_groups?: Array<string>;
    metadata?: Record<string, any>;
};

