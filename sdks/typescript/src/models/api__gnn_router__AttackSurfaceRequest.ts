/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__gnn_router__Connection } from './api__gnn_router__Connection';
import type { api__gnn_router__InfrastructureNode } from './api__gnn_router__InfrastructureNode';
import type { Vulnerability } from './Vulnerability';
/**
 * Full attack surface analysis request.
 */
export type api__gnn_router__AttackSurfaceRequest = {
    infrastructure: Array<api__gnn_router__InfrastructureNode>;
    connections: Array<api__gnn_router__Connection>;
    vulnerabilities?: Array<Vulnerability>;
};

