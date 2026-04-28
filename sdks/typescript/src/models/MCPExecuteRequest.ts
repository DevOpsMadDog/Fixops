/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for executing an MCP tool by name.
 */
export type MCPExecuteRequest = {
    /**
     * The tool name to execute
     */
    tool_name: string;
    /**
     * Arguments matching the tool's inputSchema
     */
    arguments?: Record<string, any>;
};

