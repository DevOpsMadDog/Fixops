/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Full incident response model.
 */
export type IncidentResponse = {
    id: string;
    playbook_id: string;
    title: string;
    incident_type: string;
    severity: string;
    status: string;
    current_phase: string;
    org_id: string;
    assigned_to: (string | null);
    affected_systems: Array<string>;
    affected_users: Array<string>;
    tags: Array<string>;
    phase_history: Array<Record<string, any>>;
    context: Record<string, any>;
    created_at: string;
    detected_at: (string | null);
    contained_at: (string | null);
    resolved_at: (string | null);
    updated_at: string;
    current_phase_steps: Array<Record<string, any>>;
};

