/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * For incident notification via the API.
 */
export type SlackIncidentRequest = {
    /**
     * Incident title
     */
    title: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Incident status
     */
    status?: string;
    /**
     * Incident assignee
     */
    assignee?: string;
    /**
     * Incident ID
     */
    incident_id?: (string | null);
    /**
     * Incident description
     */
    description?: (string | null);
};

