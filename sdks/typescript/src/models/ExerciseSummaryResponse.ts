/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ExerciseSummaryResponse = {
    exercise_id: string;
    name: string;
    scenario_name: string;
    category: string;
    status: string;
    scope: string;
    step_count: number;
    steps_executed: number;
    steps_detected: number;
    created_at: string;
    started_at: (string | null);
    completed_at: (string | null);
    tags: Array<string>;
};

