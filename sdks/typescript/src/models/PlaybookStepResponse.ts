/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a playbook step.
 */
export type PlaybookStepResponse = {
    step_id: string;
    step_type: string;
    name: string;
    config: Record<string, any>;
    next_on_success?: (string | null);
    next_on_failure?: (string | null);
    timeout_seconds: number;
};

