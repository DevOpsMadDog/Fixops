/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordExecutionIn = {
    /**
     * Workflow ID this execution belongs to
     */
    workflow_id: string;
    /**
     * Event that triggered this execution
     */
    trigger_event?: string;
    /**
     * Target resource ID
     */
    target_id?: string;
    /**
     * Target resource type
     */
    target_type?: string;
    /**
     * pending|running|succeeded|failed|rolled_back|skipped
     */
    status?: string;
    /**
     * ISO 8601 start time
     */
    started_at?: string;
    /**
     * ISO 8601 completion time
     */
    completed_at?: string;
    /**
     * Execution result summary
     */
    result?: string;
    /**
     * Error detail if failed
     */
    error_message?: string;
};

