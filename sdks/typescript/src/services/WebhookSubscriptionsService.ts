/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__webhook_subscriptions_router__CreateSubscriptionRequest } from '../models/apps__api__webhook_subscriptions_router__CreateSubscriptionRequest';
import type { UpdateSubscriptionRequest } from '../models/UpdateSubscriptionRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WebhookSubscriptionsService {
    /**
     * Webhook Subscriptions Health
     * @returns any Successful Response
     * @throws ApiError
     */
    public static webhookSubscriptionsHealthApiV1WebhookSubscriptionsHealthGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/health',
        });
    }
    /**
     * Webhook Subscriptions Status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static webhookSubscriptionsStatusApiV1WebhookSubscriptionsStatusGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/status',
        });
    }
    /**
     * Create Subscription
     * Create a new webhook subscription. Validates HTTPS URL, generates HMAC secret.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createSubscriptionApiV1WebhookSubscriptionsPost(
        requestBody: apps__api__webhook_subscriptions_router__CreateSubscriptionRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhook-subscriptions/',
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
     * List Subscriptions
     * List all webhook subscriptions for the current organization.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listSubscriptionsApiV1WebhookSubscriptionsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Array<Record<string, any>>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/',
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
     * Get Subscription
     * Get details of a specific webhook subscription.
     * @param subId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getSubscriptionApiV1WebhookSubscriptionsSubIdGet(
        subId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/{sub_id}',
            path: {
                'sub_id': subId,
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
     * Update Subscription
     * Update a webhook subscription.
     * @param subId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateSubscriptionApiV1WebhookSubscriptionsSubIdPut(
        subId: string,
        requestBody: UpdateSubscriptionRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/webhook-subscriptions/{sub_id}',
            path: {
                'sub_id': subId,
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
     * Delete Subscription
     * Soft-delete (deactivate) a webhook subscription.
     * @param subId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deleteSubscriptionApiV1WebhookSubscriptionsSubIdDelete(
        subId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/webhook-subscriptions/{sub_id}',
            path: {
                'sub_id': subId,
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
     * Test Subscription
     * Send a test payload to verify the webhook endpoint is reachable.
     * @param subId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testSubscriptionApiV1WebhookSubscriptionsSubIdTestPost(
        subId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhook-subscriptions/{sub_id}/test',
            path: {
                'sub_id': subId,
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
     * Delivery Log
     * Delivery retry dashboard — list all webhook delivery attempts.
     *
     * Supports filtering by subscription_id and status (success/failed).
     * Returns chronological delivery log with response codes and errors.
     * @param subscriptionId
     * @param status
     * @param limit
     * @param offset
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deliveryLogApiV1WebhookSubscriptionsDeliveryLogGet(
        subscriptionId?: (string | null),
        status?: (string | null),
        limit: number = 100,
        offset?: number,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/delivery-log',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'subscription_id': subscriptionId,
                'status': status,
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
     * Dead Letter Queue
     * Dead letter queue — subscriptions disabled due to repeated delivery failures.
     *
     * Returns subscriptions where active=0 AND failure_count >= max_retries,
     * along with their most recent delivery errors.
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deadLetterQueueApiV1WebhookSubscriptionsDeadLetterGet(
        limit: number = 50,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhook-subscriptions/dead-letter',
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
     * Retry Dead Letter
     * Retry a dead-lettered subscription — reactivate it and reset failure count.
     *
     * Sends a test delivery to verify the endpoint is now reachable.
     * If the test succeeds, the subscription is reactivated.
     * If it fails again, it stays in the dead letter queue.
     * @param subId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static retryDeadLetterApiV1WebhookSubscriptionsDeadLetterSubIdRetryPost(
        subId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhook-subscriptions/dead-letter/{sub_id}/retry',
            path: {
                'sub_id': subId,
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
}
