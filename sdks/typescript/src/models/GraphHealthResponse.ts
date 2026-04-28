/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from /health.
 */
export type GraphHealthResponse = {
    status: string;
    graph_rag_available: boolean;
    total_entities: number;
    total_relationships: number;
    cores: Record<string, any>;
};

