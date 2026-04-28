/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single event in the incident timeline.
 */
export type core__ir_playbook_engine__TimelineEvent = {
    id?: string;
    incident_id: string;
    event_type: string;
    source: string;
    description: string;
    timestamp?: string;
    metadata?: Record<string, any>;
};

