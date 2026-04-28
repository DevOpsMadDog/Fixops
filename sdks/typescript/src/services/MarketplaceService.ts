/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__marketplace_router__ContributeRequest } from '../models/apps__api__marketplace_router__ContributeRequest';
import type { apps__api__marketplace_router__RateRequest } from '../models/apps__api__marketplace_router__RateRequest';
import type { PurchaseRequest } from '../models/PurchaseRequest';
import type { UpdateRequest } from '../models/UpdateRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MarketplaceService {
    /**
     * Fetch Pack
     * Fetch a remediation pack for a specific framework and control.
     * @param framework
     * @param control
     * @returns any Successful Response
     * @throws ApiError
     */
    public static fetchPackApiV1MarketplacePacksFrameworkControlGet(
        framework: string,
        control: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/packs/{framework}/{control}',
            path: {
                'framework': framework,
                'control': control,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Browse Marketplace
     * Browse and search marketplace items with optional filters.
     * @param contentType Filter by content type
     * @param complianceFramework Filter by compliance framework
     * @param ssdlcStage Filter by SSDLC stage
     * @param pricingModel Filter by pricing model
     * @param query Search query
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static browseMarketplaceApiV1MarketplaceBrowseGet(
        contentType?: (string | null),
        complianceFramework?: (string | null),
        ssdlcStage?: (string | null),
        pricingModel?: (string | null),
        query?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/browse',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'content_type': contentType,
                'compliance_framework': complianceFramework,
                'ssdlc_stage': ssdlcStage,
                'pricing_model': pricingModel,
                'query': query,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Recommendations
     * Get recommended marketplace content based on organization profile.
     * @param organizationType Organization type
     * @param complianceRequirements Comma-separated compliance frameworks
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRecommendationsApiV1MarketplaceRecommendationsGet(
        organizationType: string = 'general',
        complianceRequirements: string = '',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/recommendations',
            query: {
                'organization_type': organizationType,
                'compliance_requirements': complianceRequirements,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Item
     * Get details of a specific marketplace item.
     * @param itemId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getItemApiV1MarketplaceItemsItemIdGet(
        itemId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/items/{item_id}',
            path: {
                'item_id': itemId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Item
     * Update an existing marketplace item.
     * @param itemId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateItemApiV1MarketplaceItemsItemIdPut(
        itemId: string,
        requestBody: UpdateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/marketplace/items/{item_id}',
            path: {
                'item_id': itemId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Contribute Content
     * Submit new content to the marketplace.
     * @param author Author name
     * @param organization Organization name
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static contributeContentApiV1MarketplaceContributePost(
        author: string,
        organization: string,
        requestBody: apps__api__marketplace_router__ContributeRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/marketplace/contribute',
            query: {
                'author': author,
                'organization': organization,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Rate Item
     * Rate a marketplace item.
     * @param itemId
     * @param reviewer Reviewer name
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static rateItemApiV1MarketplaceItemsItemIdRatePost(
        itemId: string,
        reviewer: string,
        requestBody: apps__api__marketplace_router__RateRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/marketplace/items/{item_id}/rate',
            path: {
                'item_id': itemId,
            },
            query: {
                'reviewer': reviewer,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Purchase Item
     * Purchase a marketplace item and get download token.
     * @param itemId
     * @param purchaser Purchaser name
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static purchaseItemApiV1MarketplacePurchaseItemIdPost(
        itemId: string,
        purchaser: string,
        requestBody: PurchaseRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/marketplace/purchase/{item_id}',
            path: {
                'item_id': itemId,
            },
            query: {
                'purchaser': purchaser,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Download Content
     * Download purchased content using a valid token.
     * @param token
     * @returns any Successful Response
     * @throws ApiError
     */
    public static downloadContentApiV1MarketplaceDownloadTokenGet(
        token: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/download/{token}',
            path: {
                'token': token,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Contributors
     * Get contributor leaderboard and metrics.
     * @param author Filter by author
     * @param organization Filter by organization
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getContributorsApiV1MarketplaceContributorsGet(
        author?: (string | null),
        organization?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/contributors',
            query: {
                'author': author,
                'organization': organization,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Compliance Content
     * Get marketplace content for a specific SSDLC stage and frameworks.
     * @param stage
     * @param frameworks Comma-separated compliance frameworks
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getComplianceContentApiV1MarketplaceComplianceContentStageGet(
        stage: string,
        frameworks: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/compliance-content/{stage}',
            path: {
                'stage': stage,
            },
            query: {
                'frameworks': frameworks,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Marketplace Stats
     * Get marketplace statistics and quality summary.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getMarketplaceStatsApiV1MarketplaceStatsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/stats',
        });
    }
    /**
     * Marketplace Health
     * Marketplace health check.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static marketplaceHealthApiV1MarketplaceHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/health',
        });
    }
    /**
     * Marketplace Status
     * Marketplace status (alias for /health).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static marketplaceStatusApiV1MarketplaceStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/marketplace/status',
        });
    }
}
