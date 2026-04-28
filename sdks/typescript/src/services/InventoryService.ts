/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApplicationResponse } from '../models/ApplicationResponse';
import type { ApplicationUpdate } from '../models/ApplicationUpdate';
import type { apps__api__inventory_router__ApplicationCreate } from '../models/apps__api__inventory_router__ApplicationCreate';
import type { Body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post } from '../models/Body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post';
import type { PaginatedAssetResponse } from '../models/PaginatedAssetResponse';
import type { PaginatedResponse } from '../models/PaginatedResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class InventoryService {
    /**
     * List Assets
     * List all assets across the inventory.
     *
     * Returns a unified view of all asset types (applications, services, APIs).
     * @param assetType Filter by asset type: application, service, api
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedAssetResponse Successful Response
     * @throws ApiError
     */
    public static listAssetsApiV1InventoryAssetsGet(
        assetType?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedAssetResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/assets',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'asset_type': assetType,
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Applications
     * List all applications with pagination.
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns PaginatedResponse Successful Response
     * @throws ApiError
     */
    public static listApplicationsApiV1InventoryApplicationsGet(
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<PaginatedResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'offset': offset,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Application
     * Register a new application.
     * @param requestBody
     * @returns ApplicationResponse Successful Response
     * @throws ApiError
     */
    public static createApplicationApiV1InventoryApplicationsPost(
        requestBody: apps__api__inventory_router__ApplicationCreate,
    ): CancelablePromise<ApplicationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/applications',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Application
     * Get application details by ID.
     * @param id
     * @returns ApplicationResponse Successful Response
     * @throws ApiError
     */
    public static getApplicationApiV1InventoryApplicationsIdGet(
        id: string,
    ): CancelablePromise<ApplicationResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Application
     * Update an application.
     * @param id
     * @param requestBody
     * @returns ApplicationResponse Successful Response
     * @throws ApiError
     */
    public static updateApplicationApiV1InventoryApplicationsIdPut(
        id: string,
        requestBody: ApplicationUpdate,
    ): CancelablePromise<ApplicationResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/inventory/applications/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete Application
     * Archive an application.
     * @param id
     * @returns void
     * @throws ApiError
     */
    public static deleteApplicationApiV1InventoryApplicationsIdDelete(
        id: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/inventory/applications/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Application Components
     * List components for an application (derived from dependencies).
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listApplicationComponentsApiV1InventoryApplicationsIdComponentsGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}/components',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Application Apis
     * List API endpoints for an application.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listApplicationApisApiV1InventoryApplicationsIdApisGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}/apis',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Application Dependencies
     * Upload dependency manifest for an application.
     *
     * Each dependency: {name, version, type, license, ecosystem, transitive}.
     * @param id
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPost(
        id: string,
        requestBody: Array<Record<string, any>>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/applications/{id}/dependencies',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Application Dependencies
     * Get dependency graph for an application with transitive resolution.
     * @param id
     * @param includeTransitive
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getApplicationDependenciesApiV1InventoryApplicationsIdDependenciesGet(
        id: string,
        includeTransitive: boolean = true,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}/dependencies',
            path: {
                'id': id,
            },
            query: {
                'include_transitive': includeTransitive,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Services
     * List all services with pagination.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listServicesApiV1InventoryServicesGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/services',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Service
     * Register a new service.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createServiceApiV1InventoryServicesPost(
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/services',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Service
     * Get service details by ID.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getServiceApiV1InventoryServicesIdGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/services/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Apis
     * List all API endpoints with pagination.
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listApisApiV1InventoryApisGet(
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/apis',
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Api
     * Register a new API endpoint.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createApiApiV1InventoryApisPost(
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/apis',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Api Security
     * Get security posture for an API endpoint.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getApiSecurityApiV1InventoryApisIdSecurityGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/apis/{id}/security',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Search Inventory
     * Search across all inventory types.
     * @param q
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static searchInventoryApiV1InventorySearchGet(
        q: string,
        limit: number = 100,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/search',
            query: {
                'q': q,
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Check License Compliance
     * Check license compliance for all dependencies of an application.
     *
     * Flags copyleft and restrictive licenses that may conflict with commercial use.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static checkLicenseComplianceApiV1InventoryApplicationsIdLicenseComplianceGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}/license-compliance',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Generate Sbom
     * Generate Software Bill of Materials in CycloneDX or SPDX format.
     * @param id
     * @param format
     * @returns any Successful Response
     * @throws ApiError
     */
    public static generateSbomApiV1InventoryApplicationsIdSbomGet(
        id: string,
        format: string = 'cyclonedx',
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/applications/{id}/sbom',
            path: {
                'id': id,
            },
            query: {
                'format': format,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Global Sbom Components
     * List all SBOM components across all applications.
     *
     * Aggregates components from all ingested SBOMs for enterprise-wide
     * supply chain visibility. Supports filtering by ecosystem, vulnerability
     * status, and license type.
     * @param ecosystem
     * @param hasVulnerabilities
     * @param licenseType
     * @param page
     * @param pageSize
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listGlobalSbomComponentsApiV1InventorySbomComponentsGet(
        ecosystem?: (string | null),
        hasVulnerabilities?: (boolean | null),
        licenseType?: (string | null),
        page: number = 1,
        pageSize: number = 50,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/sbom/components',
            query: {
                'ecosystem': ecosystem,
                'has_vulnerabilities': hasVulnerabilities,
                'license_type': licenseType,
                'page': page,
                'page_size': pageSize,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get License Compliance Summary
     * Get enterprise-wide license compliance summary.
     *
     * Analyzes all known components for license risk, copyleft contamination,
     * and policy violations. Critical for defense/government procurement
     * (DFARS 252.227-7014 compliance).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getLicenseComplianceSummaryApiV1InventorySbomLicensesGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/sbom/licenses',
        });
    }
    /**
     * Ingest Sbom
     * Ingest a CycloneDX or SPDX SBOM and register all components.
     *
     * Accepts standard CycloneDX 1.4+ or SPDX 2.3 format.
     * Components are parsed, deduplicated, and stored for license
     * compliance analysis and vulnerability correlation.
     * @param appId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestSbomApiV1InventorySbomIngestPost(
        appId: string,
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/sbom/ingest',
            query: {
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
     * Analyze Sbom Vulnerabilities
     * Analyze an SBOM for known vulnerabilities and generate a VEX document.
     *
     * Accepts CycloneDX or SPDX format. Cross-references all components against
     * the embedded vulnerability database, returns findings with severity
     * breakdown and auto-generates an OpenVEX companion document.
     * @param appId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static analyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePost(
        appId: string,
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/sbom/analyze',
            query: {
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
     * Apply Vex To Sbom
     * Apply VEX status to an SBOM, enriching components with exploitability info.
     *
     * If no vex_data is provided, uses the stored VEX document for the app_id.
     * Returns the SBOM with vulnerability status annotations on each component.
     * @param requestBody
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static applyVexToSbomApiV1InventorySbomVexApplyPost(
        requestBody: Body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post,
        appId?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/sbom/vex/apply',
            query: {
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
     * Get Vex Document
     * Retrieve the stored VEX document for an application.
     * @param appId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getVexDocumentApiV1InventorySbomVexAppIdGet(
        appId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/inventory/sbom/vex/{app_id}',
            path: {
                'app_id': appId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Ingest Vex Document
     * Ingest an external OpenVEX document for an application.
     *
     * Parses the document, validates structure, and stores it for
     * later application to SBOMs via /sbom/vex/apply.
     * @param appId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ingestVexDocumentApiV1InventorySbomVexIngestPost(
        appId: string,
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/inventory/sbom/vex/ingest',
            query: {
                'app_id': appId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
