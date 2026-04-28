/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Validated request for creating a Knowledge Graph edge.
 */
export type EdgeCreateRequest = {
    source_id: string;
    target_id: string;
    edge_type: string;
    properties?: Record<string, any>;
    confidence?: number;
};

