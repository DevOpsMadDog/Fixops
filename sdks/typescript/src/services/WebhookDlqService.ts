/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__webhook_dlq_router__EnqueueRequest } from '../models/apps__api__webhook_dlq_router__EnqueueRequest';
import type { ReplayBatchRequest } from '../models/ReplayBatchRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WebhookDlqService {
    /**
     * List Deliveries
     * List webhook deliveries for the current organization, with optional filters.
     * @param status Filter by status
     * @param webhookId Filter by webhook_id
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listDeliveriesApiV1WebhooksDlqGet(
        status?: (string | null),
        webhookId?: (string | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/dlq/',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'status': status,
                'webhook_id': webhookId,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Enqueue Delivery
     * Manually enqueue a webhook delivery into the DLQ.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static enqueueDeliveryApiV1WebhooksDlqEnqueuePost(
        requestBody: apps__api__webhook_dlq_router__EnqueueRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/dlq/enqueue',
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
     * List Pending
     * Return deliveries ready for retry (next_retry_at <= now).
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPendingApiV1WebhooksDlqPendingGet(
        limit: number = 100,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/dlq/pending',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Dead Letters
     * Return all dead-lettered deliveries for the current organization.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listDeadLettersApiV1WebhooksDlqDeadLettersGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/dlq/dead-letters',
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
     * Dlq Stats
     * Return DLQ status counts (pending, retrying, delivered, dead) for the org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dlqStatsApiV1WebhooksDlqStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/dlq/stats',
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
     * Failure Analytics
     * Return failure analytics: failure rate by webhook, top errors, avg retries.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static failureAnalyticsApiV1WebhooksDlqAnalyticsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/dlq/analytics',
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
     * Replay Delivery
     * Reset a dead-lettered delivery for manual replay.
     * @param deliveryId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static replayDeliveryApiV1WebhooksDlqDeliveryIdReplayPost(
        deliveryId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/dlq/{delivery_id}/replay',
            path: {
                'delivery_id': deliveryId,
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
     * Replay Batch
     * Bulk reset deliveries for manual replay.
     *
     * Returns the count of deliveries successfully reset.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static replayBatchApiV1WebhooksDlqReplayBatchPost(
        requestBody: ReplayBatchRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/dlq/replay-batch',
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
     * Purge Delivered
     * Delete delivered records older than `days` days.
     * @param days
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static purgeDeliveredApiV1WebhooksDlqPurgeDeliveredDelete(
        days: number = 30,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/webhooks/dlq/purge/delivered',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'days': days,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Purge Dead Letters
     * Delete all dead-lettered deliveries for the current organization.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static purgeDeadLettersApiV1WebhooksDlqPurgeDeadLettersDelete(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/webhooks/dlq/purge/dead-letters',
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
}
