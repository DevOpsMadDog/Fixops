/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookTrigger } from './PlaybookTrigger';
/**
 * A SOAR playbook definition with trigger, conditions, and actions.
 */
export type SOARPlaybook = {
    id?: string;
    name: string;
    trigger: PlaybookTrigger;
    conditions?: Record<string, any>;
    actions?: Array<Record<string, any>>;
    enabled?: boolean;
    execution_count?: number;
    avg_response_seconds?: number;
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

