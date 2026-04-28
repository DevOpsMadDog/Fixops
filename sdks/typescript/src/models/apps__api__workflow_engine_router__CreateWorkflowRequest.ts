/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriggerType } from './TriggerType';
import type { WorkflowActionRequest } from './WorkflowActionRequest';
import type { WorkflowConditionRequest } from './WorkflowConditionRequest';
export type apps__api__workflow_engine_router__CreateWorkflowRequest = {
    name: string;
    description?: (string | null);
    trigger: TriggerType;
    conditions?: Array<WorkflowConditionRequest>;
    actions?: Array<WorkflowActionRequest>;
    enabled?: boolean;
    org_id?: string;
    created_by?: string;
};

