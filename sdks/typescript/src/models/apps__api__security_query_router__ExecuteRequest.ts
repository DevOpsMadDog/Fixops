/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_query_router__ExecuteRequest = {
    /**
     * DSL query text
     */
    dsl: string;
    /**
     * Tenant identifier
     */
    org_id: string;
    /**
     * memory | sqlite
     */
    provider?: string;
    /**
     * Optional saved query id
     */
    query_id?: (string | null);
};

