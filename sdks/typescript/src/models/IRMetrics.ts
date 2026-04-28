/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Aggregate IR metrics for an org.
 */
export type IRMetrics = {
    org_id: string;
    total_incidents: number;
    active_incidents: number;
    closed_incidents: number;
    mean_time_to_detect_hours: number;
    mean_time_to_contain_hours: number;
    mean_time_to_resolve_hours: number;
    incidents_by_type: Record<string, number>;
    incidents_by_severity: Record<string, number>;
    playbook_effectiveness: Record<string, number>;
};

