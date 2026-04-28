/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__algorithmic_router__Connection } from './api__algorithmic_router__Connection';
import type { api__algorithmic_router__InfrastructureNode } from './api__algorithmic_router__InfrastructureNode';
/**
 * Request for critical node identification.
 */
export type CriticalNodeRequest = {
    infrastructure: Array<api__algorithmic_router__InfrastructureNode>;
    connections: Array<api__algorithmic_router__Connection>;
    top_k?: number;
};

