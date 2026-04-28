/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__stream_router__PublishRequest } from '../models/apps__api__stream_router__PublishRequest';
import type { EventChannel } from '../models/EventChannel';
import type { PublishResponse } from '../models/PublishResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class EventStreamService {
    /**
     * Server-Sent Events stream for a channel
     * Stream events for *channel* as Server-Sent Events.
     *
     * The client receives:
     * - An initial burst of up to 10 recent events (if replay=true)
     * - A ``ping`` heartbeat comment every 15 seconds
     * - New events as they are published
     *
     * SSE format::
     *
     * id: <uuid>
     * event: <event_type>
     * data: {"id": "…", "event_type": "…", "data": {…}, …}
     * @param channel
     * @param orgId Filter to this org
     * @param replay Replay last 10 events on connect
     * @param apiKey Optional API key
     * @returns any Successful Response
     * @throws ApiError
     */
    public static sseStreamApiV1StreamSseChannelGet(
        channel: EventChannel,
        orgId?: (string | null),
        replay: boolean = true,
        apiKey?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/stream/sse/{channel}',
            path: {
                'channel': channel,
            },
            query: {
                'org_id': orgId,
                'replay': replay,
                'api_key': apiKey,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Publish an event to a channel
     * Publish a single event to *channel*.
     *
     * The event is immediately delivered to all active SSE/WebSocket subscribers
     * on that channel and stored in the ring-buffer for late-joining clients.
     * @param requestBody
     * @returns PublishResponse Successful Response
     * @throws ApiError
     */
    public static publishEventApiV1StreamPublishPost(
        requestBody: apps__api__stream_router__PublishRequest,
    ): CancelablePromise<PublishResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/stream/publish',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Event stream statistics
     * Return per-channel statistics:
     * - events_per_channel
     * - subscribers_per_channel
     * - history_size_per_channel
     * - total_published / total_subscribers
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getStatsApiV1StreamStatsGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/stream/stats',
        });
    }
    /**
     * Get recent events for a channel
     * Return the last *limit* events from *channel*, newest first.
     *
     * Useful for dashboard initial load before subscribing to SSE/WS.
     * @param channel
     * @param limit
     * @param orgId Filter to this org
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getRecentApiV1StreamRecentChannelGet(
        channel: EventChannel,
        limit: number = 20,
        orgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/stream/recent/{channel}',
            path: {
                'channel': channel,
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
}
