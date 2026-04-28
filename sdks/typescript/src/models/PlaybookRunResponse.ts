/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__playbook_routes__StepResultResponse } from './apps__api__playbook_routes__StepResultResponse';
/**
 * Response model for a playbook run.
 */
export type PlaybookRunResponse = {
    run_id: string;
    playbook_id: string;
    trigger_event: Record<string, any>;
    status: string;
    started_at: string;
    completed_at?: (string | null);
    step_results: Array<apps__api__playbook_routes__StepResultResponse>;
    error?: (string | null);
    org_id: string;
    duration_seconds: number;
};

