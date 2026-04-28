/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__jira_sync_router__SyncAllRequest } from '../models/apps__api__jira_sync_router__SyncAllRequest';
import type { apps__api__jira_sync_router__SyncFindingRequest } from '../models/apps__api__jira_sync_router__SyncFindingRequest';
import type { apps__api__jira_sync_router__SyncStatusRequest } from '../models/apps__api__jira_sync_router__SyncStatusRequest';
import type { apps__api__servicenow_sync_router__ConfigureRequest } from '../models/apps__api__servicenow_sync_router__ConfigureRequest';
import type { apps__api__servicenow_sync_router__ConfigureResponse } from '../models/apps__api__servicenow_sync_router__ConfigureResponse';
import type { apps__api__servicenow_sync_router__FieldMappingItem } from '../models/apps__api__servicenow_sync_router__FieldMappingItem';
import type { apps__api__servicenow_sync_router__FieldMappingUpdateRequest } from '../models/apps__api__servicenow_sync_router__FieldMappingUpdateRequest';
import type { apps__api__servicenow_sync_router__HistoryEntry } from '../models/apps__api__servicenow_sync_router__HistoryEntry';
import type { apps__api__servicenow_sync_router__StatsResponse } from '../models/apps__api__servicenow_sync_router__StatsResponse';
import type { apps__api__servicenow_sync_router__SyncAllResponse } from '../models/apps__api__servicenow_sync_router__SyncAllResponse';
import type { apps__api__servicenow_sync_router__SyncResultResponse } from '../models/apps__api__servicenow_sync_router__SyncResultResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class ServicenowSyncService {
    /**
     * Configure ServiceNow sync engine
     * Set (and persist) the ServiceNow connection configuration and sync policy.
     *
     * The configuration is stored in the sync engine's SQLite database and
     * survives process restarts.
     * @param requestBody
     * @returns apps__api__servicenow_sync_router__ConfigureResponse Successful Response
     * @throws ApiError
     */
    public static configureApiV1ServicenowSyncConfigurePost(
        requestBody: apps__api__servicenow_sync_router__ConfigureRequest,
    ): CancelablePromise<apps__api__servicenow_sync_router__ConfigureResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/servicenow-sync/configure',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sync a batch of findings to ServiceNow
     * Push a list of findings to ServiceNow, creating or updating incidents as needed.
     *
     * Each finding dict must contain a ``finding_id`` or ``id`` field.
     * Returns per-finding results and aggregate counters.
     * @param requestBody
     * @returns apps__api__servicenow_sync_router__SyncAllResponse Successful Response
     * @throws ApiError
     */
    public static syncAllApiV1ServicenowSyncSyncAllPost(
        requestBody: apps__api__jira_sync_router__SyncAllRequest,
    ): CancelablePromise<apps__api__servicenow_sync_router__SyncAllResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/servicenow-sync/sync-all',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sync a single finding to ServiceNow
     * Create or update the ServiceNow incident that corresponds to the given finding.
     *
     * If a ServiceNow link already exists for this finding the incident is updated.
     * If no link exists a new incident is created and the link is recorded.
     * @param requestBody
     * @returns apps__api__servicenow_sync_router__SyncResultResponse Successful Response
     * @throws ApiError
     */
    public static syncFindingApiV1ServicenowSyncSyncFindingPost(
        requestBody: apps__api__jira_sync_router__SyncFindingRequest,
    ): CancelablePromise<apps__api__servicenow_sync_router__SyncResultResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/servicenow-sync/sync-finding',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Propagate finding status change to ServiceNow
     * Update the linked ServiceNow incident state to reflect the finding's new status.
     *
     * Requires a pre-existing link between ``finding_id`` and a ServiceNow incident
     * (established via ``sync-finding``). Uses the configured
     * ``finding_to_sn_state`` mapping to determine the ServiceNow state code.
     * @param requestBody
     * @returns apps__api__servicenow_sync_router__SyncResultResponse Successful Response
     * @throws ApiError
     */
    public static syncStatusApiV1ServicenowSyncSyncStatusPost(
        requestBody: apps__api__jira_sync_router__SyncStatusRequest,
    ): CancelablePromise<apps__api__servicenow_sync_router__SyncResultResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/servicenow-sync/sync-status',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Retrieve current field mapping configuration
     * Return the list of custom finding-field → ServiceNow-field mappings.
     *
     * These mappings supplement the built-in ones (title, severity, description).
     * @returns apps__api__servicenow_sync_router__FieldMappingItem Successful Response
     * @throws ApiError
     */
    public static getFieldMappingApiV1ServicenowSyncFieldMappingGet(): CancelablePromise<Array<apps__api__servicenow_sync_router__FieldMappingItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/servicenow-sync/field-mapping',
        });
    }
    /**
     * Replace field mapping configuration
     * Replace the entire custom field mapping list.
     *
     * The new list is persisted immediately and takes effect on the next sync.
     * @param requestBody
     * @returns apps__api__servicenow_sync_router__FieldMappingItem Successful Response
     * @throws ApiError
     */
    public static updateFieldMappingApiV1ServicenowSyncFieldMappingPut(
        requestBody: apps__api__servicenow_sync_router__FieldMappingUpdateRequest,
    ): CancelablePromise<Array<apps__api__servicenow_sync_router__FieldMappingItem>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/servicenow-sync/field-mapping',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Paginated sync history
     * Return the sync audit history, newest first.
     *
     * Optionally filter to a specific ``finding_id``. Supports pagination via
     * ``limit`` and ``offset``.
     * @param findingId Filter by finding ID
     * @param limit Max records to return
     * @param offset Number of records to skip
     * @returns apps__api__servicenow_sync_router__HistoryEntry Successful Response
     * @throws ApiError
     */
    public static getHistoryApiV1ServicenowSyncHistoryGet(
        findingId?: (string | null),
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<Array<apps__api__servicenow_sync_router__HistoryEntry>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/servicenow-sync/history',
            query: {
                'finding_id': findingId,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sync engine statistics
     * Return aggregate statistics: total links, event counts by status and direction.
     * @returns apps__api__servicenow_sync_router__StatsResponse Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1ServicenowSyncStatsGet(): CancelablePromise<apps__api__servicenow_sync_router__StatsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/servicenow-sync/stats',
        });
    }
    /**
     * Receive ServiceNow webhook events
     * Receive and process ServiceNow webhook ``POST`` callbacks.
     *
     * ServiceNow Business Rules or Flow Designer POST a JSON payload for every
     * incident event (insert, update, delete). The engine translates the
     * ServiceNow state into an ALDECI finding status and records the event in
     * sync history.
     *
     * Expected payload keys:
     * - ``sys_id``        — ServiceNow sys_id of the incident
     * - ``number``        — incident number (e.g. INC0010042)
     * - ``state``         — state code (1=New, 2=In Progress, 6=Resolved, 7=Closed)
     * - ``table_name``    — should be ``incident``
     * - ``action``        — ``insert`` | ``update`` | ``delete``
     * - ``sys_updated_on``— ISO timestamp of the last update
     *
     * If ``webhook_secret`` is configured the engine validates it against the
     * ``X-ServiceNow-Webhook-Secret`` request header.
     * @returns apps__api__servicenow_sync_router__SyncResultResponse Successful Response
     * @throws ApiError
     */
    public static handleWebhookApiV1ServicenowSyncWebhooksPost(): CancelablePromise<apps__api__servicenow_sync_router__SyncResultResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/servicenow-sync/webhooks',
        });
    }
}
