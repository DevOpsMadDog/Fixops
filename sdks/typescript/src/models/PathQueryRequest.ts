/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__gnn_router__Connection } from './api__gnn_router__Connection';
import type { api__gnn_router__InfrastructureNode } from './api__gnn_router__InfrastructureNode';
/**
 * Request to find attack paths between specific nodes.
 */
export type PathQueryRequest = {
    infrastructure: Array<api__gnn_router__InfrastructureNode>;
    connections: Array<api__gnn_router__Connection>;
    entry_points: Array<string>;
    targets: Array<string>;
    max_paths?: number;
    max_depth?: number;
};

