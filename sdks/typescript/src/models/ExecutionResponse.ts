/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__ir_playbook_runner_router__StepResultResponse } from './apps__api__ir_playbook_runner_router__StepResultResponse';
export type ExecutionResponse = {
    execution_id: string;
    playbook_id: string;
    incident_id: string;
    started_at: string;
    completed_at: (string | null);
    status: string;
    steps_total: number;
    steps_completed: number;
    current_step: (string | null);
    step_results: Array<apps__api__ir_playbook_runner_router__StepResultResponse>;
};

