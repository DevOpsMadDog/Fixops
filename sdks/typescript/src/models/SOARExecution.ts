/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ExecutionStatus } from './ExecutionStatus';
/**
 * A record of a SOAR playbook execution.
 */
export type SOARExecution = {
    id?: string;
    playbook_id: string;
    trigger_event?: Record<string, any>;
    actions_taken?: Array<Record<string, any>>;
    started_at?: string;
    completed_at?: (string | null);
    status?: ExecutionStatus;
    org_id?: string;
    error_message?: (string | null);
};

