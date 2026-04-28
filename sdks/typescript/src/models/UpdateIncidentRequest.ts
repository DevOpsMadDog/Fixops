/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for updating a PagerDuty incident.
 */
export type UpdateIncidentRequest = {
    /**
     * New status: 'acknowledged' or 'resolved'
     */
    status?: (string | null);
    /**
     * New incident title
     */
    title?: (string | null);
    /**
     * New urgency: 'high' or 'low'
     */
    urgency?: (string | null);
    /**
     * Resolution note
     */
    resolution?: (string | null);
};

