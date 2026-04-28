/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type OnboardingProgressResponse = {
    org_id: string;
    current_step: string;
    steps: Record<string, string>;
    started_at: string;
    completed_at?: (string | null);
    completion_percentage: number;
};

