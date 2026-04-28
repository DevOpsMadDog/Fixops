/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateQueryRequest = {
    name: string;
    /**
     * HuntCategory value
     */
    category: string;
    /**
     * Matching logic (any/all conditions)
     */
    query_logic: Record<string, any>;
    /**
     * critical|high|medium|low|info
     */
    severity?: string;
    description?: string;
    mitre_tactic?: string;
};

