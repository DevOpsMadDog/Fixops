/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Single step in a DR runbook.
 */
export type RunbookStep = {
    step_number: number;
    title: string;
    description: string;
    responsible_party: string;
    estimated_duration_minutes?: number;
    dependencies?: Array<number>;
    validation_criteria?: (string | null);
};

