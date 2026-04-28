/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BatchCorrelateRequest } from '../models/BatchCorrelateRequest';
import type { BulkLookupRequest } from '../models/BulkLookupRequest';
import type { Campaign } from '../models/Campaign';
import type { CorrelateRequest } from '../models/CorrelateRequest';
import type { IOCLookupRequest } from '../models/IOCLookupRequest';
import type { ThreatActor } from '../models/ThreatActor';
import type { ThreatCorrelation } from '../models/ThreatCorrelation';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ThreatIntelService {
    /**
     * Correlate Finding
     * Correlate a single security finding against all known threat actors
     * and campaigns. Returns the best-matching ThreatCorrelation.
     * @param requestBody
     * @returns ThreatCorrelation Successful Response
     * @throws ApiError
     */
    public static correlateFindingApiV1ThreatIntelCorrelatePost(
        requestBody: CorrelateRequest,
    ): CancelablePromise<ThreatCorrelation> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/correlate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Correlate Batch
     * Correlate a batch of security findings. Returns a correlation result
     * for each finding in the same order as the input list.
     * @param requestBody
     * @returns ThreatCorrelation Successful Response
     * @throws ApiError
     */
    public static correlateBatchApiV1ThreatIntelCorrelateBatchPost(
        requestBody: BatchCorrelateRequest,
    ): CancelablePromise<Array<ThreatCorrelation>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/correlate/batch',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Threat Actors
     * List all registered threat actor profiles. Optionally filter to
     * active actors only.
     * @param activeOnly Return only active actors
     * @returns ThreatActor Successful Response
     * @throws ApiError
     */
    public static listThreatActorsApiV1ThreatIntelActorsGet(
        activeOnly: boolean = false,
    ): CancelablePromise<Array<ThreatActor>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/actors',
            query: {
                'active_only': activeOnly,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Threat Actor
     * Register a new threat actor profile. If an actor with the same ID
     * already exists it will be replaced (upsert).
     * @param requestBody
     * @returns ThreatActor Successful Response
     * @throws ApiError
     */
    public static addThreatActorApiV1ThreatIntelActorsPost(
        requestBody: ThreatActor,
    ): CancelablePromise<ThreatActor> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/actors',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Actor Profile
     * Return full actor dossier: profile, associated campaigns, and
     * recent finding correlations.
     * @param actorId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getActorProfileApiV1ThreatIntelActorsActorIdGet(
        actorId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/actors/{actor_id}',
            path: {
                'actor_id': actorId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Campaign
     * Register a new threat campaign. Upserts on duplicate ID.
     * @param requestBody
     * @returns Campaign Successful Response
     * @throws ApiError
     */
    public static addCampaignApiV1ThreatIntelCampaignsPost(
        requestBody: Campaign,
    ): CancelablePromise<Campaign> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/campaigns',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Campaigns
     * Return known threat actor campaigns from the ThreatIntelCorrelator store.
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listCampaignsApiV1ThreatIntelCampaignsGet(
        limit: number = 50,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/campaigns',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Campaign Timeline
     * Return campaign details and all correlated finding events as a
     * chronological timeline.
     * @param campaignId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet(
        campaignId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/campaigns/{campaign_id}/timeline',
            path: {
                'campaign_id': campaignId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Threat Landscape
     * Return a high-level threat landscape overview for the organisation:
     * active actor count, active campaigns, and top correlated threat actors.
     * @param orgId Organisation identifier
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getThreatLandscapeApiV1ThreatIntelLandscapeGet(
        orgId: string = 'default',
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/landscape',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Active Threats
     * Return all currently active threat actors relevant to the organisation.
     * @param orgId Organisation identifier
     * @returns ThreatActor Successful Response
     * @throws ApiError
     */
    public static getActiveThreatsApiV1ThreatIntelActiveThreatsGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<ThreatActor>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/active-threats',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Recent Cves
     * Return the most recently cached CVEs enriched with EPSS scores.
     *
     * CVEs are served from the local SQLite cache. Call ``/refresh`` to
     * pull the latest data from NVD / EPSS / CISA KEV.
     * @param limit Max CVEs to return
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRecentCvesApiV1ThreatIntelCvesRecentGet(
        limit: number = 100,
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/cves/recent',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Kev Catalog
     * Return the current CISA Known Exploited Vulnerabilities catalog from cache.
     *
     * The catalog is refreshed on each call to ``/refresh``.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getKevCatalogApiV1ThreatIntelKevGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/kev',
        });
    }
    /**
     * Trigger Refresh
     * Trigger a fresh pull from NVD, EPSS, and CISA KEV.
     *
     * This is a synchronous operation — it blocks until all feeds
     * are fetched and cached. For large date ranges this may take
     * up to 60 seconds due to NVD rate limits.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static triggerRefreshApiV1ThreatIntelRefreshPost(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/refresh',
        });
    }
    /**
     * List Iocs
     * List/search IOCs from local feed caches.
     *
     * Currently returns C2 IPs from the Feodo blocklist.
     * Supports optional substring search and type filtering.
     * @param iocType Filter by type: ip|domain|hash|url
     * @param search Substring search on IOC value
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listIocsApiV1ThreatIntelIocsGet(
        iocType?: (string | null),
        search?: (string | null),
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/iocs',
            query: {
                'ioc_type': iocType,
                'search': search,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Lookup Ioc
     * Lookup a specific IOC value across all available feeds.
     *
     * Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
     * Returns all matching feed hits plus auto-detected IOC type.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static lookupIocApiV1ThreatIntelIocsLookupPost(
        requestBody: IOCLookupRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/iocs/lookup',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Feeds Status
     * Return status of all configured threat intelligence feeds.
     *
     * Reports: name, last_updated, ioc_count, health status.
     * Feeds without API keys report health=no_api_key.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFeedsStatusApiV1ThreatIntelFeedsStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/feeds/status',
        });
    }
    /**
     * Get Feeds Summary
     * Aggregated stats: total IOCs, counts by type and source.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getFeedsSummaryApiV1ThreatIntelFeedsSummaryGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/feeds/summary',
        });
    }
    /**
     * Bulk Lookup Iocs
     * Check a list of IOC values against all available feeds.
     *
     * Returns a result entry for each value with found/hits.
     * Limited to 100 values per request.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static bulkLookupIocsApiV1ThreatIntelIocsBulkLookupPost(
        requestBody: BulkLookupRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/threat-intel/iocs/bulk-lookup',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Trending Threats
     * Return trending threats this week — most recently active C2 IPs from Feodo.
     * @param limit Number of trending IOCs to return
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getTrendingThreatsApiV1ThreatIntelTrendingGet(
        limit: number = 10,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/trending',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Ip Geo
     * Return geo/ASN/reputation data for an IP address.
     *
     * Uses Shodan InternetDB (no auth required) for open port/vuln data.
     * Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
     * Checks Feodo C2 blocklist for C2 classification.
     * @param ip
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getIpGeoApiV1ThreatIntelGeoIpGet(
        ip: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/threat-intel/geo/{ip}',
            path: {
                'ip': ip,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
