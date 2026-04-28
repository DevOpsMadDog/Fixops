/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_graph_router__AddEdgeRequest = {
    /**
     * Source node ID
     */
    source_id: string;
    /**
     * Target node ID
     */
    target_id: string;
    /**
     * EdgeType value
     */
    type: string;
    /**
     * Edge metadata
     */
    metadata?: Record<string, any>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

