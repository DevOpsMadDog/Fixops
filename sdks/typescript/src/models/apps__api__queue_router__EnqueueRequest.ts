/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__queue_router__EnqueueRequest = {
    /**
     * Category / type of task (e.g. 'scan', 'alert')
     */
    task_type: string;
    /**
     * Arbitrary task payload
     */
    payload?: Record<string, any>;
    /**
     * Priority 1=highest, 10=lowest
     */
    priority?: number;
};

