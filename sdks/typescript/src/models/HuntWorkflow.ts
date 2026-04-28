/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntStatus } from './HuntStatus';
import type { HuntTriggerType } from './HuntTriggerType';
/**
 * A structured threat hunt workflow.
 */
export type HuntWorkflow = {
    id?: string;
    hypothesis_id: string;
    hypothesis_name: string;
    org_id: string;
    status?: HuntStatus;
    trigger_type?: HuntTriggerType;
    trigger_context?: Record<string, any>;
    analyst?: string;
    started_at?: (string | null);
    completed_at?: (string | null);
    findings_count?: number;
    data_sources_queried?: Array<string>;
    notes?: string;
    created_at?: string;
};

