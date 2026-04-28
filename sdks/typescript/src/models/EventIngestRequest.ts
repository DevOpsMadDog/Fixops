/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EventType } from './EventType';
import type { ThreatLevel } from './ThreatLevel';
/**
 * Request body for ingesting a runtime event.
 */
export type EventIngestRequest = {
    event_type: EventType;
    source_host: string;
    process_name: string;
    user: string;
    details?: Record<string, any>;
    threat_level?: ThreatLevel;
};

