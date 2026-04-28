/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TriggerType } from './TriggerType';
import type { WorkflowActionRequest } from './WorkflowActionRequest';
import type { WorkflowConditionRequest } from './WorkflowConditionRequest';
export type UpdateWorkflowRequest = {
    name?: (string | null);
    description?: (string | null);
    trigger?: (TriggerType | null);
    conditions?: (Array<WorkflowConditionRequest> | null);
    actions?: (Array<WorkflowActionRequest> | null);
    enabled?: (boolean | null);
};

