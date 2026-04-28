/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__cloud_discovery_router__DiscoverRequest } from '../models/apps__api__cloud_discovery_router__DiscoverRequest';
import type { DiscoverResponse } from '../models/DiscoverResponse';
import type { DriftResponse } from '../models/DriftResponse';
import type { RegisterCMDBRequest } from '../models/RegisterCMDBRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class CloudDiscoveryService {
    /**
     * Discover AWS assets
     * Enumerate AWS resources and store them in the inventory.
     * @param requestBody
     * @returns DiscoverResponse Successful Response
     * @throws ApiError
     */
    public static discoverAwsApiV1CloudDiscoverAwsPost(
        requestBody: apps__api__cloud_discovery_router__DiscoverRequest,
    ): CancelablePromise<DiscoverResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/cloud/discover/aws',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Discover Azure assets
     * Enumerate Azure resources and store them in the inventory.
     * @param requestBody
     * @returns DiscoverResponse Successful Response
     * @throws ApiError
     */
    public static discoverAzureApiV1CloudDiscoverAzurePost(
        requestBody: apps__api__cloud_discovery_router__DiscoverRequest,
    ): CancelablePromise<DiscoverResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/cloud/discover/azure',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Discover GCP assets
     * Enumerate GCP resources and store them in the inventory.
     * @param requestBody
     * @returns DiscoverResponse Successful Response
     * @throws ApiError
     */
    public static discoverGcpApiV1CloudDiscoverGcpPost(
        requestBody: apps__api__cloud_discovery_router__DiscoverRequest,
    ): CancelablePromise<DiscoverResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/cloud/discover/gcp',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Discover assets across all cloud providers
     * Trigger discovery across AWS, Azure, and GCP simultaneously.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static discoverAllApiV1CloudDiscoverAllPost(
        requestBody: apps__api__cloud_discovery_router__DiscoverRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/cloud/discover/all',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get full cloud asset inventory
     * Return full asset inventory with optional filters.
     * @param orgId Organisation ID
     * @param provider Filter by provider: aws | azure | gcp
     * @param assetType Filter by asset type
     * @param region Filter by region
     * @param accountId Filter by account/subscription/project ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getInventoryApiV1CloudInventoryGet(
        orgId: string = 'default',
        provider?: (string | null),
        assetType?: (string | null),
        region?: (string | null),
        accountId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/cloud/inventory',
            query: {
                'org_id': orgId,
                'provider': provider,
                'asset_type': assetType,
                'region': region,
                'account_id': accountId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get unmanaged (shadow IT) assets
     * Return assets not present in the CMDB.
     * @param orgId Organisation ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getUnmanagedAssetsApiV1CloudAssetsUnmanagedGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/cloud/assets/unmanaged',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get internet-exposed assets
     * Return assets with a public IP address.
     * @param orgId Organisation ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPublicAssetsApiV1CloudAssetsPublicGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/cloud/assets/public',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get asset drift
     * Return new and removed assets within the lookback window.
     * @param orgId Organisation ID
     * @param days Lookback window in days
     * @returns DriftResponse Successful Response
     * @throws ApiError
     */
    public static getAssetDriftApiV1CloudAssetsDriftGet(
        orgId: string = 'default',
        days: number = 7,
    ): CancelablePromise<DriftResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/cloud/assets/drift',
            query: {
                'org_id': orgId,
                'days': days,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get discovery statistics
     * Return aggregated discovery stats by provider, asset type, and region.
     * @param orgId Organisation ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1CloudStatsGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/cloud/stats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Register asset as managed in CMDB
     * Mark a cloud resource as known/managed so it no longer appears as unmanaged.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerCmdbApiV1CloudCmdbRegisterPost(
        requestBody: RegisterCMDBRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/cloud/cmdb/register',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
