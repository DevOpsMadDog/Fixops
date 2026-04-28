/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Health check for the MCP auto-discovery service.
 */
export type MCPHealthResponse = {
    status: string;
    catalog_size: number;
    generated_at: (string | null);
    uptime_seconds: number;
    mcp_version?: string;
};

