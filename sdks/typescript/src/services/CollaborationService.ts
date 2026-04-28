/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddWatcherRequest } from '../models/AddWatcherRequest';
import type { apps__api__collaboration_router__AddCommentRequest } from '../models/apps__api__collaboration_router__AddCommentRequest';
import type { apps__api__collaboration_router__RecordActivityRequest } from '../models/apps__api__collaboration_router__RecordActivityRequest';
import type { DeliverNotificationRequest } from '../models/DeliverNotificationRequest';
import type { NotifyWatchersRequest } from '../models/NotifyWatchersRequest';
import type { ProcessNotificationsRequest } from '../models/ProcessNotificationsRequest';
import type { QueueNotificationRequest } from '../models/QueueNotificationRequest';
import type { UpdateNotificationPreferencesRequest } from '../models/UpdateNotificationPreferencesRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class CollaborationService {
    /**
     * Add Comment
     * Add a comment to an entity.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addCommentApiV1CollaborationCommentsPost(
        requestBody: apps__api__collaboration_router__AddCommentRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/comments',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Comments
     * Get comments for an entity. If entity_type/entity_id omitted, returns recent comments.
     * @param entityType
     * @param entityId
     * @param includeInternal
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getCommentsApiV1CollaborationCommentsGet(
        entityType?: (string | null),
        entityId?: (string | null),
        includeInternal: boolean = true,
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/comments',
            query: {
                'entity_type': entityType,
                'entity_id': entityId,
                'include_internal': includeInternal,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Promote To Evidence
     * Promote a comment to evidence for compliance.
     * @param commentId
     * @param promotedBy
     * @returns any Successful Response
     * @throws ApiError
     */
    public static promoteToEvidenceApiV1CollaborationCommentsCommentIdPromotePut(
        commentId: string,
        promotedBy: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/collaboration/comments/{comment_id}/promote',
            path: {
                'comment_id': commentId,
            },
            query: {
                'promoted_by': promotedBy,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add Watcher
     * Add a watcher to an entity.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addWatcherApiV1CollaborationWatchersPost(
        requestBody: AddWatcherRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/watchers',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Remove Watcher
     * Remove a watcher from an entity.
     * @param entityType
     * @param entityId
     * @param userId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static removeWatcherApiV1CollaborationWatchersDelete(
        entityType: string,
        entityId: string,
        userId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/collaboration/watchers',
            query: {
                'entity_type': entityType,
                'entity_id': entityId,
                'user_id': userId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Watchers
     * Get watchers for an entity.
     * @param entityType
     * @param entityId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getWatchersApiV1CollaborationWatchersGet(
        entityType: string,
        entityId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/watchers',
            query: {
                'entity_type': entityType,
                'entity_id': entityId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Watched Entities
     * Get entities watched by a user.
     * @param userId
     * @param entityType
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getWatchedEntitiesApiV1CollaborationWatchersUserUserIdGet(
        userId: string,
        entityType?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/watchers/user/{user_id}',
            path: {
                'user_id': userId,
            },
            query: {
                'entity_type': entityType,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Record Activity
     * Record an activity in the feed.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static recordActivityApiV1CollaborationActivitiesPost(
        requestBody: apps__api__collaboration_router__RecordActivityRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/activities',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Activity Feed
     * Get activity feed with optional filters.
     * @param orgId
     * @param entityType
     * @param entityId
     * @param activityTypes
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getActivityFeedApiV1CollaborationActivitiesGet(
        orgId: string,
        entityType?: (string | null),
        entityId?: (string | null),
        activityTypes?: (string | null),
        limit: number = 50,
        offset?: number,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/activities',
            query: {
                'org_id': orgId,
                'entity_type': entityType,
                'entity_id': entityId,
                'activity_types': activityTypes,
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get User Mentions
     * Get mentions for a user.
     * @param userId
     * @param unacknowledgedOnly
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getUserMentionsApiV1CollaborationMentionsUserIdGet(
        userId: string,
        unacknowledgedOnly: boolean = false,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/mentions/{user_id}',
            path: {
                'user_id': userId,
            },
            query: {
                'unacknowledged_only': unacknowledgedOnly,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Acknowledge Mention
     * Acknowledge a mention.
     * @param mentionId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static acknowledgeMentionApiV1CollaborationMentionsMentionIdAcknowledgePut(
        mentionId: number,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/collaboration/mentions/{mention_id}/acknowledge',
            path: {
                'mention_id': mentionId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Entity Types
     * List all valid entity types.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listEntityTypesApiV1CollaborationEntityTypesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/entity-types',
        });
    }
    /**
     * List Activity Types
     * List all valid activity types.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listActivityTypesApiV1CollaborationActivityTypesGet(): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/activity-types',
        });
    }
    /**
     * Queue Notification
     * Queue a notification for delivery.
     *
     * Notification types:
     * - new_critical_finding: New critical/high severity finding
     * - status_change: Finding/task status changed
     * - comment_mention: User was mentioned in a comment
     * - sla_breach: SLA deadline approaching or breached
     * - assignment: Task/finding assigned to user
     *
     * Priority levels: low, normal, high, urgent
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static queueNotificationApiV1CollaborationNotificationsQueuePost(
        requestBody: QueueNotificationRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/notifications/queue',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Notify Watchers
     * Notify all watchers of an entity.
     *
     * This is a convenience endpoint that:
     * 1. Gets all watchers for the entity
     * 2. Queues notifications for each watcher
     * 3. Returns summary of notifications queued
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static notifyWatchersApiV1CollaborationNotificationsNotifyWatchersPost(
        requestBody: NotifyWatchersRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/notifications/notify-watchers',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Pending Notifications
     * Get pending notifications for delivery.
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPendingNotificationsApiV1CollaborationNotificationsPendingGet(
        limit: number = 100,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/notifications/pending',
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mark Notification Sent
     * Mark a notification as sent or failed.
     * @param notificationId
     * @param error
     * @returns any Successful Response
     * @throws ApiError
     */
    public static markNotificationSentApiV1CollaborationNotificationsNotificationIdSentPut(
        notificationId: string,
        error?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/collaboration/notifications/{notification_id}/sent',
            path: {
                'notification_id': notificationId,
            },
            query: {
                'error': error,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Notification Preferences
     * Get notification preferences for a user.
     * @param userId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getNotificationPreferencesApiV1CollaborationNotificationsPreferencesUserIdGet(
        userId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/notifications/preferences/{user_id}',
            path: {
                'user_id': userId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Notification Preferences
     * Update notification preferences for a user.
     *
     * Digest frequency options: immediate, hourly, daily, weekly
     * @param userId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updateNotificationPreferencesApiV1CollaborationNotificationsPreferencesUserIdPut(
        userId: string,
        requestBody: UpdateNotificationPreferencesRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/collaboration/notifications/preferences/{user_id}',
            path: {
                'user_id': userId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Deliver Notification
     * Deliver a specific notification via configured channels.
     *
     * Supports Slack webhook and/or email (SMTP) delivery.
     * Respects user notification preferences.
     *
     * Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
     * variable to prevent SSRF attacks.
     * @param notificationId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static deliverNotificationApiV1CollaborationNotificationsNotificationIdDeliverPost(
        notificationId: string,
        requestBody: DeliverNotificationRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/notifications/{notification_id}/deliver',
            path: {
                'notification_id': notificationId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Process Pending Notifications
     * Process all pending notifications in the queue.
     *
     * This is the main worker endpoint that should be called periodically
     * (e.g., by a cron job or scheduler) to deliver queued notifications.
     *
     * Supports Slack webhook and/or email (SMTP) delivery.
     * Respects user notification preferences.
     *
     * Note: Slack webhook URL is read from FIXOPS_SLACK_WEBHOOK_URL environment
     * variable to prevent SSRF attacks.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static processPendingNotificationsApiV1CollaborationNotificationsProcessPost(
        requestBody: ProcessNotificationsRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/collaboration/notifications/process',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Collaboration Channels
     * List collaboration channels/war rooms.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static collaborationChannelsApiV1CollaborationChannelsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/channels',
        });
    }
    /**
     * Collaboration Health
     * Collaboration service health check.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static collaborationHealthApiV1CollaborationHealthGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/health',
        });
    }
    /**
     * Collaboration Status
     * Collaboration service status (alias for /health).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static collaborationStatusApiV1CollaborationStatusGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/collaboration/status',
        });
    }
}
