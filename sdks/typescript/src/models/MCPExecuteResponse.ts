/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from MCP tool execution.
 */
export type MCPExecuteResponse = {
    tool_name: string;
    method: string;
    path: string;
    status: string;
    status_code: number;
    result?: any;
    error?: (string | null);
    execution_time_ms?: number;
};

