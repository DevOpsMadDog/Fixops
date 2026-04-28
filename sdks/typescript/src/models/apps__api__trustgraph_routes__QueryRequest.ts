/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Natural language query request.
 */
export type apps__api__trustgraph_routes__QueryRequest = {
    /**
     * Natural language query
     */
    query: string;
    /**
     * Cores to query
     */
    target_cores?: (Array<number> | null);
    /**
     * Maximum results per core
     */
    max_results?: (number | null);
};

