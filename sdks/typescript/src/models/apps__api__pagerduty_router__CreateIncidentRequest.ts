/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for creating a PagerDuty incident.
 */
export type apps__api__pagerduty_router__CreateIncidentRequest = {
    /**
     * Incident summary / title
     */
    title: string;
    /**
     * PagerDuty service ID
     */
    service_id: string;
    /**
     * Incident urgency: 'high' or 'low'
     */
    urgency?: string;
    /**
     * Incident body details (plain text)
     */
    body_details?: (string | null);
    /**
     * Override escalation policy ID
     */
    escalation_policy_id?: (string | null);
    /**
     * Priority object ID
     */
    priority_id?: (string | null);
};

