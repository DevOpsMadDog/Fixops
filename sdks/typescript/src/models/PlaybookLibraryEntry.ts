/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookStepSummary } from './PlaybookStepSummary';
export type PlaybookLibraryEntry = {
    playbook_id: string;
    name: string;
    description: string;
    trigger_conditions: Array<string>;
    severity_threshold: string;
    step_count: number;
    steps: Array<PlaybookStepSummary>;
};

