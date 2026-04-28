/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AgentType } from './AgentType';
/**
 * Request for multi-agent orchestration.
 */
export type OrchestrateRequest = {
    objective: string;
    agents?: Array<AgentType>;
    context?: Record<string, any>;
    max_iterations?: number;
};

