/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /retrieve.
 */
export type RetrieveRequest = {
    /**
     * Natural language security query
     */
    query: string;
    /**
     * Max seed entities
     */
    top_k?: number;
    /**
     * Relationship traversal depth
     */
    hops?: number;
};

