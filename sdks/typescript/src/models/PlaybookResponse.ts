/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookStepResponse } from './PlaybookStepResponse';
/**
 * Response model for a playbook.
 */
export type PlaybookResponse = {
    playbook_id: string;
    name: string;
    description: string;
    trigger_conditions: Record<string, any>;
    steps: Array<PlaybookStepResponse>;
    status: string;
    version: number;
    created_by: string;
    org_id: string;
    tags: Array<string>;
};

