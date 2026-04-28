/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AnalyzeAccountRequest = {
    /**
     * AWS account ID (12-digit)
     */
    account_id: string;
    /**
     * List of {principal: str, policy: dict} objects
     */
    policies: Array<Record<string, any>>;
};

