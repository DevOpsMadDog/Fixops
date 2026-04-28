/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPToolDefinition } from '../models/MCPToolDefinition';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class McpDiscoveryService {
    /**
     * Mcp Status
     * Status alias for MCP auto-discovery (mirrors /health).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static mcpStatusApiV1McpStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/status',
        });
    }
    /**
     * List Mcp Tools
     * Return the complete MCP tool catalog with optional filtering.
     *
     * This endpoint returns auto-discovered tools generated from all FastAPI
     * routes registered in the application. Tools are generated once at
     * startup and cached for performance.
     *
     * Supports filtering by category (query/action/analysis), tag, HTTP method,
     * and free-text search across tool names and descriptions.
     * @param category Filter by category: query, action, analysis
     * @param tag Filter by tag
     * @param method Filter by HTTP method: GET, POST, PUT, DELETE, PATCH
     * @param search Search tool names and descriptions
     * @param deprecated Filter by deprecation status
     * @param limit Max tools to return
     * @param offset Offset for pagination
     * @returns MCPToolDefinition Successful Response
     * @throws ApiError
     */
    public static listMcpToolsApiV1McpToolsGet(
        category?: (string | null),
        tag?: (string | null),
        method?: (string | null),
        search?: (string | null),
        deprecated?: (boolean | null),
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<Array<MCPToolDefinition>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/tools',
            query: {
                'category': category,
                'tag': tag,
                'method': method,
                'search': search,
                'deprecated': deprecated,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Mcp Manifest
     * Return the MCP server manifest for IDE/agent configuration.
     *
     * This returns JSON that can be added to VS Code settings (.vscode/mcp.json),
     * Cursor (.cursor/mcp.json), or Claude Desktop config.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMcpManifestApiV1McpManifestGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/manifest',
        });
    }
}
