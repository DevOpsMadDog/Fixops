/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPTransport } from './MCPTransport';
/**
 * MCP server configuration.
 */
export type MCPServerConfig = {
    enabled?: boolean;
    transport?: MCPTransport;
    port?: number;
    allowed_origins?: Array<string>;
    require_auth?: boolean;
    exposed_tools?: Array<string>;
    exposed_resources?: Array<string>;
    rate_limit_per_minute?: number;
};

