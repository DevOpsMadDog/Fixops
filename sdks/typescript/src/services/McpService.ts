/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MCPClient } from '../models/MCPClient';
import type { MCPClientStatus } from '../models/MCPClientStatus';
import type { MCPConfigureRequest } from '../models/MCPConfigureRequest';
import type { MCPPrompt } from '../models/MCPPrompt';
import type { MCPResource } from '../models/MCPResource';
import type { MCPServerConfig } from '../models/MCPServerConfig';
import type { MCPToolCallRequest } from '../models/MCPToolCallRequest';
import type { MCPToolCallResponse } from '../models/MCPToolCallResponse';
import { MCPTransport } from '../models/MCPTransport';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class McpService {
    /**
     * List Mcp Clients
     * List connected MCP clients.
     * @param status
     * @param clientType
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPClient Successful Response
     * @throws ApiError
     */
    public static listMcpClientsApiV1McpClientsGet(
        status?: (MCPClientStatus | null),
        clientType?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<MCPClient>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/clients',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'status': status,
                'client_type': clientType,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Mcp Resources
     * List available MCP resources.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPResource Successful Response
     * @throws ApiError
     */
    public static listMcpResourcesApiV1McpResourcesGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<MCPResource>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/resources',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Mcp Prompts
     * List available MCP prompts.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPPrompt Successful Response
     * @throws ApiError
     */
    public static listMcpPromptsApiV1McpPromptsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<MCPPrompt>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/prompts',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Mcp Config
     * Get current MCP server configuration.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPServerConfig Successful Response
     * @throws ApiError
     */
    public static getMcpConfigApiV1McpConfigGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<MCPServerConfig> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/mcp/config',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Configure Mcp Server
     * Update MCP server configuration.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPServerConfig Successful Response
     * @throws ApiError
     */
    public static configureMcpServerApiV1McpConfigurePost(
        requestBody: MCPConfigureRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<MCPServerConfig> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mcp/configure',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Disconnect Client
     * Disconnect an MCP client.
     * @param clientId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static disconnectClientApiV1McpClientsClientIdDisconnectPost(
        clientId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mcp/clients/{client_id}/disconnect',
            path: {
                'client_id': clientId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove Client
     * Remove an MCP client registration.
     * @param clientId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static removeClientApiV1McpClientsClientIdDelete(
        clientId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/mcp/clients/{client_id}',
            path: {
                'client_id': clientId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Call Mcp Tool
     * Execute an MCP tool. This is the core execution endpoint that wires
     * MCP tool calls to actual FixOps backend engines.
     *
     * Supports all 8 registered MCP tools:
     * - fixops_list_findings / fixops_get_finding
     * - fixops_run_scan
     * - fixops_generate_evidence
     * - fixops_create_autofix_pr
     * - fixops_get_risk_score
     * - fixops_list_connectors
     * - fixops_notify
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MCPToolCallResponse Successful Response
     * @throws ApiError
     */
    public static callMcpToolApiV1McpToolsCallPost(
        requestBody: MCPToolCallRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<MCPToolCallResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mcp/tools/call',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Register Mcp Client
     * Register a new MCP client connection.
     * @param name
     * @param clientType
     * @param transport
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerMcpClientApiV1McpClientsRegisterPost(
        name: string = 'anonymous',
        clientType: string = 'agent',
        transport: MCPTransport = MCPTransport.HTTP_SSE,
        orgId?: (string | null),
        xOrgId?: (string | null),
        requestBody?: Array<string>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/mcp/clients/register',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'name': name,
                'client_type': clientType,
                'transport': transport,
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
