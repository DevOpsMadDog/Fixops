/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from an MCP tool execution.
 */
export type MCPToolCallResponse = {
    tool_name: string;
    success: boolean;
    result?: any;
    error?: (string | null);
    execution_time_ms?: number;
};

