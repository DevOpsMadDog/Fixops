/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__app_config_router__HealthResponse } from '../models/apps__api__app_config_router__HealthResponse';
import type { apps__api__app_config_router__RegisterAppRequest } from '../models/apps__api__app_config_router__RegisterAppRequest';
import type { AppSummary } from '../models/AppSummary';
import type { ClassificationValidationResponse } from '../models/ClassificationValidationResponse';
import type { SLAResponse } from '../models/SLAResponse';
import type { UpdateAppRequest } from '../models/UpdateAppRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AppIdConfigurationService {
    /**
     * Health check
     * Return API and database health status.
     * @returns apps__api__app_config_router__HealthResponse Successful Response
     * @throws ApiError
     */
    public static healthCheckApiV1AppsHealthGet(): CancelablePromise<apps__api__app_config_router__HealthResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/health',
        });
    }
    /**
     * Register a new app from aldeci.yaml
     * Register a new application from an aldeci.yaml payload.
     *
     * Accepts either ``yaml_content`` (raw YAML string) or ``config`` (parsed dict).
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerAppApiV1AppsPost(
        requestBody: apps__api__app_config_router__RegisterAppRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/apps/',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all apps
     * Return a list of all registered, non-deleted apps.
     *
     * Optionally filter by ``org_id``.
     * @param orgId Filter by organisation ID
     * @returns AppSummary Successful Response
     * @throws ApiError
     */
    public static listAppsApiV1AppsGet(
        orgId?: (string | null),
    ): CancelablePromise<Array<AppSummary>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get app details with components
     * Retrieve the full configuration for a given ``app_id``.
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAppApiV1AppsAppIdGet(
        appId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update app config
     * Apply a partial update to an existing app config.
     *
     * Top-level keys in ``updates`` are merged into the current config.
     * Nested dicts (e.g. ``policies``) are shallow-merged.
     * @param appId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateAppApiV1AppsAppIdPut(
        appId: string,
        requestBody: UpdateAppRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/apps/{app_id}',
            path: {
                'app_id': appId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Soft delete an app
     * Soft-delete an application by setting its ``deleted_at`` timestamp.
     *
     * The config is retained in the database for audit and evidence retention purposes.
     * @param appId
     * @returns string Successful Response
     * @throws ApiError
     */
    public static deleteAppApiV1AppsAppIdDelete(
        appId: string,
    ): CancelablePromise<Record<string, string>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/apps/{app_id}',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List components for an app
     * Return all component configurations for the given ``app_id``.
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listComponentsApiV1AppsAppIdComponentsGet(
        appId: string,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/components',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get a specific component
     * Retrieve configuration for a single named component.
     * @param appId
     * @param name
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComponentApiV1AppsAppIdComponentsNameGet(
        appId: string,
        name: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/components/{name}',
            path: {
                'app_id': appId,
                'name': name,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get SLA deadline for a severity
     * Return the SLA configuration and computed deadline UTC timestamp for the given severity.
     *
     * Optionally scoped to a specific ``component``.
     * @param appId
     * @param severity
     * @param component Component name for component-specific SLA
     * @returns SLAResponse Successful Response
     * @throws ApiError
     */
    public static getSlaApiV1AppsAppIdSlaSeverityGet(
        appId: string,
        severity: string,
        component?: (string | null),
    ): CancelablePromise<SLAResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/sla/{severity}',
            path: {
                'app_id': appId,
                'severity': severity,
            },
            query: {
                'component': component,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get scanner assignments
     * Return all scanner category assignments for the given app.
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getScannersApiV1AppsAppIdScannersGet(
        appId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/scanners',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get policy config
     * Return the security and compliance policies for the given app.
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPoliciesApiV1AppsAppIdPoliciesGet(
        appId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/policies',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Validate classification consistency
     * Validate that policy classification level is appropriate for data classification.
     *
     * Checks include:
     * - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
     * - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
     * - ITAR in compliance list must have itar_controlled = true
     * - Air-gapped environments should not reference cloud-only scanners
     * @param appId
     * @returns ClassificationValidationResponse Successful Response
     * @throws ApiError
     */
    public static validateClassificationApiV1AppsAppIdValidatePost(
        appId: string,
    ): CancelablePromise<ClassificationValidationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/apps/{app_id}/validate',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export config as aldeci.yaml
     * Export the full app configuration as a downloadable ``aldeci.yaml`` string.
     *
     * The response is plain text with content-type ``text/yaml``.
     * @param appId
     * @returns string Successful Response
     * @throws ApiError
     */
    public static exportConfigApiV1AppsAppIdExportGet(
        appId: string,
    ): CancelablePromise<string> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/apps/{app_id}/export',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
