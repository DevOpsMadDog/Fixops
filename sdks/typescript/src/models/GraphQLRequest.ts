/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Standard GraphQL over HTTP request body.
 */
export type GraphQLRequest = {
    /**
     * GraphQL query or mutation document
     */
    query: string;
    /**
     * Optional variable map merged with inline arguments
     */
    variables?: (Record<string, any> | null);
    /**
     * Optional operation name (informational only)
     */
    operation_name?: (string | null);
};

