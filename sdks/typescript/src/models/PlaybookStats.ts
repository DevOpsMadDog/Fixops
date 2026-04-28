/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Aggregate statistics for SOAR playbooks in an org.
 */
export type PlaybookStats = {
    org_id: string;
    total_playbooks: number;
    enabled_playbooks: number;
    total_executions: number;
    completed_executions: number;
    failed_executions: number;
    avg_response_seconds: number;
    executions_by_trigger: Record<string, number>;
};

