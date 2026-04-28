/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single item in the smart triage queue.
 */
export type TriageQueueItem = {
    finding_id: string;
    title: string;
    severity: string;
    priority_score: number;
    sla_deadline: string;
    sla_urgency: number;
    attack_path_count?: number;
    bucket: string;
};

