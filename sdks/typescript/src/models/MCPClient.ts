/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPClientStatus } from './MCPClientStatus';
import type { MCPTransport } from './MCPTransport';
/**
 * An MCP client connection.
 */
export type MCPClient = {
    id: string;
    name: string;
    client_type: string;
    status: MCPClientStatus;
    transport: MCPTransport;
    connected_at?: (string | null);
    last_activity_at?: (string | null);
    capabilities?: Array<string>;
    metadata?: Record<string, any>;
};

