/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPTransport } from './MCPTransport';
/**
 * Request to configure MCP server.
 */
export type MCPConfigureRequest = {
    enabled?: (boolean | null);
    transport?: (MCPTransport | null);
    port?: (number | null);
    allowed_origins?: (Array<string> | null);
    require_auth?: (boolean | null);
    exposed_tools?: (Array<string> | null);
    rate_limit_per_minute?: (number | null);
};

