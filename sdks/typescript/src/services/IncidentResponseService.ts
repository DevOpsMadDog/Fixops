/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AdvancePhaseRequest } from '../models/AdvancePhaseRequest';
import type { apps__api__ir_playbook_router__AddEvidenceRequest } from '../models/apps__api__ir_playbook_router__AddEvidenceRequest';
import type { apps__api__ir_playbook_router__CreateIncidentRequest } from '../models/apps__api__ir_playbook_router__CreateIncidentRequest';
import type { core__ir_playbook_engine__TimelineEvent } from '../models/core__ir_playbook_engine__TimelineEvent';
import type { EvidenceResponse } from '../models/EvidenceResponse';
import type { IncidentResponse } from '../models/IncidentResponse';
import type { IRMetrics } from '../models/IRMetrics';
import type { NotificationResponse } from '../models/NotificationResponse';
import type { PlaybookSummary } from '../models/PlaybookSummary';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class IncidentResponseService {
    /**
     * List IR Playbooks
     * Return all 15 built-in NIST 800-61 incident response playbooks.
     * @returns PlaybookSummary Successful Response
     * @throws ApiError
     */
    public static listPlaybooksApiV1IrPlaybooksGet(): CancelablePromise<Array<PlaybookSummary>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/playbooks',
        });
    }
    /**
     * Create Incident
     * Create a new incident. Auto-selects the matching NIST 800-61 playbook. Automatically creates regulatory notification deadlines for applicable frameworks.
     * @param requestBody
     * @returns IncidentResponse Successful Response
     * @throws ApiError
     */
    public static createIncidentApiV1IrIncidentsPost(
        requestBody: apps__api__ir_playbook_router__CreateIncidentRequest,
    ): CancelablePromise<IncidentResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ir/incidents',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Incident
     * Retrieve an incident by ID including current NIST phase and pending steps.
     * @param incidentId
     * @param orgId Organization ID
     * @returns IncidentResponse Successful Response
     * @throws ApiError
     */
    public static getIncidentApiV1IrIncidentsIncidentIdGet(
        incidentId: string,
        orgId: string = 'default',
    ): CancelablePromise<IncidentResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/incidents/{incident_id}',
            path: {
                'incident_id': incidentId,
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
     * Advance Incident Phase
     * Advance incident to the next NIST 800-61 phase: Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned → Closed.
     * @param incidentId
     * @param requestBody
     * @param orgId Organization ID
     * @returns IncidentResponse Successful Response
     * @throws ApiError
     */
    public static advancePhaseApiV1IrIncidentsIncidentIdAdvancePost(
        incidentId: string,
        requestBody: AdvancePhaseRequest,
        orgId: string = 'default',
    ): CancelablePromise<IncidentResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ir/incidents/{incident_id}/advance',
            path: {
                'incident_id': incidentId,
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
     * Get Incident Timeline
     * Return chronological timeline of all events, actions, and communications for the incident.
     * @param incidentId
     * @param orgId Organization ID
     * @returns core__ir_playbook_engine__TimelineEvent Successful Response
     * @throws ApiError
     */
    public static getTimelineApiV1IrIncidentsIncidentIdTimelineGet(
        incidentId: string,
        orgId: string = 'default',
    ): CancelablePromise<Array<core__ir_playbook_engine__TimelineEvent>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/incidents/{incident_id}/timeline',
            path: {
                'incident_id': incidentId,
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
     * Get Evidence Chain
     * Return the cryptographically-linked evidence chain for an incident. Each item includes SHA-256 hash, collector ID, and chain integrity status.
     * @param incidentId
     * @param orgId Organization ID
     * @returns EvidenceResponse Successful Response
     * @throws ApiError
     */
    public static getEvidenceChainApiV1IrIncidentsIncidentIdEvidenceGet(
        incidentId: string,
        orgId: string = 'default',
    ): CancelablePromise<Array<EvidenceResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/incidents/{incident_id}/evidence',
            path: {
                'incident_id': incidentId,
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
     * Add Evidence
     * Add a piece of evidence to the incident with cryptographic chain-of-custody.
     * @param incidentId
     * @param requestBody
     * @param orgId Organization ID
     * @returns EvidenceResponse Successful Response
     * @throws ApiError
     */
    public static addEvidenceApiV1IrIncidentsIncidentIdEvidencePost(
        incidentId: string,
        requestBody: apps__api__ir_playbook_router__AddEvidenceRequest,
        orgId: string = 'default',
    ): CancelablePromise<EvidenceResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ir/incidents/{incident_id}/evidence',
            path: {
                'incident_id': incidentId,
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
     * IR Metrics Dashboard
     * Return incident response metrics: MTTD, MTTC, MTTR, incident counts by type/severity, and playbook effectiveness scores.
     * @param orgId Organization ID
     * @returns IRMetrics Successful Response
     * @throws ApiError
     */
    public static getMetricsApiV1IrMetricsGet(
        orgId: string = 'default',
    ): CancelablePromise<IRMetrics> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/metrics',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Regulatory Notification Deadlines
     * Return all regulatory notification deadlines and status: GDPR (72h), HIPAA (60d), PCI-DSS (immediate), CCPA (30d), SOC2, NIST. Includes hours remaining and generated notification templates.
     * @param orgId Organization ID
     * @param incidentId Filter by incident ID
     * @returns NotificationResponse Successful Response
     * @throws ApiError
     */
    public static getNotificationsApiV1IrNotificationsGet(
        orgId: string = 'default',
        incidentId?: (string | null),
    ): CancelablePromise<Array<NotificationResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ir/notifications',
            query: {
                'org_id': orgId,
                'incident_id': incidentId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Mark Notification Sent
     * Record that a regulatory notification has been filed with the relevant authority.
     * @param notificationId
     * @param orgId Organization ID
     * @returns NotificationResponse Successful Response
     * @throws ApiError
     */
    public static markNotificationSentApiV1IrNotificationsNotificationIdMarkSentPost(
        notificationId: string,
        orgId: string = 'default',
    ): CancelablePromise<NotificationResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ir/notifications/{notification_id}/mark-sent',
            path: {
                'notification_id': notificationId,
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
