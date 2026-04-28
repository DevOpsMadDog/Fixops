/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateTicketRequest } from '../models/CreateTicketRequest';
import type { RegisterConnectorRequest } from '../models/RegisterConnectorRequest';
import type { ScanFleetRequest } from '../models/ScanFleetRequest';
import type { ScanTenantRequest } from '../models/ScanTenantRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ConnectorsService {
    /**
     * Status
     * Report tool availability + fleet readiness.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static statusApiV1ConnectorsSnykOssStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/snyk-oss/status',
        });
    }
    /**
     * Tenants
     * @returns any Successful Response
     * @throws ApiError
     */
    public static tenantsApiV1ConnectorsSnykOssTenantsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/snyk-oss/tenants',
        });
    }
    /**
     * Scan Tenant
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanTenantApiV1ConnectorsSnykOssScanPost(
        requestBody: ScanTenantRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/snyk-oss/scan',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Scan Fleet
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanFleetApiV1ConnectorsSnykOssScanFleetPost(
        requestBody: ScanFleetRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/snyk-oss/scan-fleet',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List supported connector types
     * Return all supported connector types and their required configuration fields.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listConnectorTypesApiV1ConnectorsTypesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/types',
        });
    }
    /**
     * List registered connectors
     * Return metadata for all registered connectors.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listConnectorsApiV1ConnectorsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors',
        });
    }
    /**
     * Register a new connector
     * Register a Jira, GitHub, or Slack connector.
     *
     * Credentials are validated for format but not tested against the
     * remote API. Use POST /test after registration to verify connectivity.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerConnectorApiV1ConnectorsRegisterPost(
        requestBody: RegisterConnectorRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/register',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Test all connectors
     * Test connectivity to all registered connectors.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testAllConnectorsApiV1ConnectorsTestPost(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/test',
        });
    }
    /**
     * Create ticket from finding
     * Create tickets across one or more connectors from a security finding.
     *
     * If no targets are specified, tickets are created on ALL registered
     * connectors. Each connector runs independently -- if Jira fails,
     * GitHub and Slack still execute.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createTicketApiV1ConnectorsCreateTicketPost(
        requestBody: CreateTicketRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/create-ticket',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Test a specific connector
     * Test connectivity to a specific registered connector.
     * @param name
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testConnectorApiV1ConnectorsNameTestPost(
        name: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/connectors/{name}/test',
            path: {
                'name': name,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove a connector
     * Unregister and remove a connector.
     * @param name
     * @returns any Successful Response
     * @throws ApiError
     */
    public static removeConnectorApiV1ConnectorsNameDelete(
        name: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/connectors/{name}',
            path: {
                'name': name,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Connectors health
     * Return health status of the connectors subsystem.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static connectorsHealthApiV1ConnectorsHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/connectors/health',
        });
    }
}
