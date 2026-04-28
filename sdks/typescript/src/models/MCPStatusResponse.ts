/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPTransport } from './MCPTransport';
/**
 * MCP server status.
 */
export type MCPStatusResponse = {
    enabled: boolean;
    transport: MCPTransport;
    connected_clients: number;
    available_tools: number;
    available_resources: number;
    available_prompts: number;
    uptime_seconds: number;
    version?: string;
};

