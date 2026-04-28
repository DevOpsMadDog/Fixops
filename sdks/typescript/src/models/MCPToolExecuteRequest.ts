/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Execute a tool via the MCP protocol layer.
 */
export type MCPToolExecuteRequest = {
    /**
     * Name of the tool to execute
     */
    tool_name: string;
    /**
     * Tool arguments
     */
    arguments?: Record<string, any>;
    /**
     * Optional session context
     */
    session_id?: (string | null);
};

