/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { api__algorithmic_router__Connection } from './api__algorithmic_router__Connection';
import type { api__algorithmic_router__InfrastructureNode } from './api__algorithmic_router__InfrastructureNode';
import type { VulnerabilityNode } from './VulnerabilityNode';
/**
 * Request for attack surface analysis.
 */
export type api__algorithmic_router__AttackSurfaceRequest = {
    /**
     * Infrastructure nodes
     */
    infrastructure: Array<api__algorithmic_router__InfrastructureNode>;
    /**
     * Connections
     */
    connections?: Array<api__algorithmic_router__Connection>;
    /**
     * Vulnerabilities
     */
    vulnerabilities?: Array<VulnerabilityNode>;
    /**
     * Maximum attack paths to return
     */
    max_paths?: number;
};

