/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IncidentSeverity } from './IncidentSeverity';
import type { IncidentType } from './IncidentType';
/**
 * Request body for creating a new incident.
 */
export type apps__api__ir_playbook_router__CreateIncidentRequest = {
    /**
     * Short descriptive title
     */
    title: string;
    /**
     * Type of security incident
     */
    incident_type: IncidentType;
    /**
     * Incident severity level
     */
    severity: IncidentSeverity;
    /**
     * Organization identifier
     */
    org_id?: string;
    /**
     * Responder username or team
     */
    assigned_to?: (string | null);
    /**
     * Affected system hostnames/IPs
     */
    affected_systems?: Array<string>;
    /**
     * Affected user accounts
     */
    affected_users?: Array<string>;
    /**
     * Free-form classification tags
     */
    tags?: Array<string>;
    /**
     * Additional incident context
     */
    context?: Record<string, any>;
    /**
     * Override detection timestamp (ISO-8601)
     */
    detected_at?: (string | null);
};

