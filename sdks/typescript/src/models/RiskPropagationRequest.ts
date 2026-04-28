/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__gnn_router__Connection } from './api__gnn_router__Connection';
import type { api__gnn_router__InfrastructureNode } from './api__gnn_router__InfrastructureNode';
/**
 * Request to propagate risk from specific vulnerability nodes.
 */
export type RiskPropagationRequest = {
    infrastructure: Array<api__gnn_router__InfrastructureNode>;
    connections: Array<api__gnn_router__Connection>;
    /**
     * Node IDs to propagate risk from
     */
    source_nodes: Array<string>;
    max_depth?: number;
    decay_factor?: number;
};

