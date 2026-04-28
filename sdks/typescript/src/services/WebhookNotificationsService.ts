/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__webhook_notifications_router__RegisterWebhookRequest } from '../models/apps__api__webhook_notifications_router__RegisterWebhookRequest';
import type { DispatchRequest } from '../models/DispatchRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WebhookNotificationsService {
    /**
     * List supported event types
     * Return all event types that can trigger webhook notifications.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listSupportedEventsApiV1WebhooksNotificationsEventsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/notifications/events',
        });
    }
    /**
     * Register a webhook URL
     * Register a new webhook URL with an event filter. Returns the webhook ID and signing secret.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerWebhookApiV1WebhooksNotificationsRegisterPost(
        requestBody: apps__api__webhook_notifications_router__RegisterWebhookRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/notifications/register',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List registered webhooks
     * List all registered webhooks for an organization.
     * @param orgId Organization ID
     * @param activeOnly Return only active webhooks
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listWebhooksApiV1WebhooksNotificationsGet(
        orgId: string,
        activeOnly: boolean = true,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/webhooks/notifications',
            query: {
                'org_id': orgId,
                'active_only': activeOnly,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove a webhook
     * Permanently remove a registered webhook.
     * @param webhookId
     * @param orgId Organization ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deleteWebhookApiV1WebhooksNotificationsWebhookIdDelete(
        webhookId: string,
        orgId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/webhooks/notifications/{webhook_id}',
            path: {
                'webhook_id': webhookId,
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
     * Send test payload to a webhook
     * Send a test payload to verify the webhook endpoint is reachable.
     * @param webhookId
     * @param orgId Organization ID
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testWebhookApiV1WebhooksNotificationsTestWebhookIdPost(
        webhookId: string,
        orgId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/notifications/test/{webhook_id}',
            path: {
                'webhook_id': webhookId,
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
     * Dispatch an internal event to matching webhooks
     * Fire an event to all matching active webhooks. Used by internal systems.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static dispatchEventApiV1WebhooksNotificationsDispatchPost(
        requestBody: DispatchRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/webhooks/notifications/dispatch',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
