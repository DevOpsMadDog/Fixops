/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPToolInputSchema } from './MCPToolInputSchema';
/**
 * A single MCP tool definition generated from a FastAPI route.
 */
export type MCPToolDefinition = {
    /**
     * Unique tool name derived from the route's endpoint function name
     */
    name: string;
    /**
     * Human-readable description from the endpoint docstring
     */
    description?: string;
    /**
     * JSON Schema for tool input parameters
     */
    inputSchema?: MCPToolInputSchema;
    /**
     * HTTP method (GET, POST, PUT, DELETE, PATCH)
     */
    method: string;
    /**
     * API route path
     */
    path: string;
    /**
     * OpenAPI tags
     */
    tags?: Array<string>;
    /**
     * Tool category: query, action, or analysis
     */
    category?: string;
    /**
     * Whether the endpoint requires auth
     */
    requires_auth?: boolean;
    /**
     * Whether the route is deprecated
     */
    deprecated?: boolean;
};

