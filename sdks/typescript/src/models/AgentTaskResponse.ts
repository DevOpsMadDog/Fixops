/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AgentStatus } from './AgentStatus';
import type { AgentType } from './AgentType';
/**
 * Generic agent task response.
 */
export type AgentTaskResponse = {
    task_id: string;
    agent: AgentType;
    status: AgentStatus;
    created_at: string;
    result?: (Record<string, any> | null);
    error?: (string | null);
};

