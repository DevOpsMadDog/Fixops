/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { InstalledApp } from '../models/InstalledApp';
import type { InstallRequest } from '../models/InstallRequest';
import type { IntegrationCategory } from '../models/IntegrationCategory';
import type { MarketplaceApp } from '../models/MarketplaceApp';
import type { RateAppRequest } from '../models/RateAppRequest';
import type { RegisterCustomAppRequest } from '../models/RegisterCustomAppRequest';
import type { UpdateConfigRequest } from '../models/UpdateConfigRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class IntegrationMarketplaceService {
    /**
     * List available integrations
     * Browse the integration marketplace catalog.
     *
     * Returns all public integrations plus any private apps registered by this org.
     * Optionally filter by category or text search.
     * @param category Filter by category
     * @param search Text search on name and description
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MarketplaceApp Successful Response
     * @throws ApiError
     */
    public static listAppsApiV1IntegrationsAppsGet(
        category?: (IntegrationCategory | null),
        search?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<MarketplaceApp>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/integrations/apps',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'category': category,
                'search': search,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Register a custom integration
     * Register a private/custom integration visible only to this organization.
     *
     * Useful for internal tools or custom webhook receivers not in the public catalog.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns MarketplaceApp Successful Response
     * @throws ApiError
     */
    public static registerCustomAppApiV1IntegrationsAppsPost(
        requestBody: RegisterCustomAppRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<MarketplaceApp> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/integrations/apps',
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
     * Get integration details
     * Return full details for a specific integration.
     * @param appId
     * @returns MarketplaceApp Successful Response
     * @throws ApiError
     */
    public static getAppApiV1IntegrationsAppsAppIdGet(
        appId: string,
    ): CancelablePromise<MarketplaceApp> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/integrations/apps/{app_id}',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Install an integration
     * Install a marketplace integration for the current organization.
     *
     * The configuration provided must satisfy the app's ``config_schema``.
     * Returns the created ``InstalledApp`` record.
     * @param appId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns InstalledApp Successful Response
     * @throws ApiError
     */
    public static installAppApiV1IntegrationsAppsAppIdInstallPost(
        appId: string,
        requestBody: InstallRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<InstalledApp> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/integrations/apps/{app_id}/install',
            path: {
                'app_id': appId,
            },
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
     * Uninstall an integration
     * Remove an installed integration from the current organization.
     * @param appId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns void
     * @throws ApiError
     */
    public static uninstallAppApiV1IntegrationsAppsAppIdInstallDelete(
        appId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/integrations/apps/{app_id}/install',
            path: {
                'app_id': appId,
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
     * Update integration configuration
     * Update configuration settings for an already-installed integration.
     * @param appId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns InstalledApp Successful Response
     * @throws ApiError
     */
    public static updateConfigApiV1IntegrationsAppsAppIdConfigPatch(
        appId: string,
        requestBody: UpdateConfigRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<InstalledApp> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/v1/integrations/apps/{app_id}/config',
            path: {
                'app_id': appId,
            },
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
     * List installed integrations
     * Return all integrations currently installed by this organization.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns InstalledApp Successful Response
     * @throws ApiError
     */
    public static listInstalledApiV1IntegrationsInstalledGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<InstalledApp>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/integrations/installed',
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
     * Check installed integration health
     * Perform a lightweight health check on an installed integration.
     *
     * Validates that required configuration fields are present and the app is
     * active. Returns a health report with status and details.
     * @param appId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getAppHealthApiV1IntegrationsAppsAppIdHealthGet(
        appId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/integrations/apps/{app_id}/health',
            path: {
                'app_id': appId,
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
     * Rate an integration
     * Submit or update a rating for a marketplace integration.
     *
     * Each user can rate an app once per organization; re-submitting updates
     * the existing rating. Returns the new average rating.
     * @param appId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static rateAppApiV1IntegrationsAppsAppIdRatePost(
        appId: string,
        requestBody: RateAppRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/integrations/apps/{app_id}/rate',
            path: {
                'app_id': appId,
            },
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
     * List integration categories
     * Return all available integration category names.
     * @returns string Successful Response
     * @throws ApiError
     */
    public static listCategoriesApiV1IntegrationsCategoriesGet(): CancelablePromise<Array<string>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/integrations/categories',
        });
    }
}
